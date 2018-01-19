open Core_kernel.Std
open Lwt
open Common
open Ok_parsec
open Watchdog


module IASet= Core.Std.Unix.Inet_addr.Set [@@ocaml.warning "-3"]


let cmd_notSupported ps sock_cli=
  begin%lwts
    fd_write_string sock_cli
      Msg.(request_rep CommandNotSupported anyAddr4)
      >|= ignore;
    Lwt.return (0, 0);
  end

let atyp_notSupported ps sock_cli=
  begin%lwts
    fd_write_string sock_cli
      Msg.(request_rep AddressTypeNotSupported anyAddr4)
      >|= ignore;
    Lwt.return (0, 0);
  end

let hostUnreachable ps sock_cli=
  begin%lwts
    fd_write_string sock_cli
      Msg.(request_rep HostUnreachable anyAddr4)
      >|= ignore;
    Lwt.return (0, 0);
  end

let connectionRefused ps sock_cli=
  begin%lwts
    fd_write_string sock_cli
      Msg.(request_rep ConnectionRefused anyAddr4)
      >|= ignore;
    Lwt.return (0, 0);
  end

let networkUnreachable ps sock_cli=
  begin%lwts
    fd_write_string sock_cli
      Msg.(request_rep NetworkUnreachable anyAddr4)
      >|= ignore;
    Lwt.return (0, 0);
  end


let connect ?timeout ps sock_cli dst=
  match%lwt watchdog_timeout ?timeout (connect_socksAddr SOCK_STREAM dst)
  with
  | sock_dst->
    (let addr= Msg.addr_of_sockaddr (Lwt_unix.getsockname sock_dst) in
    begin%lwts
      fd_write_string sock_cli (Msg.request_rep Msg.Succeeded addr)
        >|= ignore;
      pairStream ~ps1:ps sock_cli sock_dst;
    end)
    [%lwt.finally force_close sock_dst]
  | exception Watchdog Timeout->
    hostUnreachable ps sock_cli
  | exception Unix.Unix_error (ETIMEDOUT, f, p)->
    hostUnreachable ps sock_cli
  | exception Unix.Unix_error (ENETUNREACH, f, p)->
    hostUnreachable ps sock_cli
  | exception Unix.Unix_error (ECONNREFUSED, f, p)->
    connectionRefused ps sock_cli
  | exception Msg.Rep NetworkUnreachable->
    networkUnreachable ps sock_cli


let bind ?timeout ps sock_cli dst=
  let%lwt dst_addr= resolv_addr dst in
  let domain= Unix.domain_of_sockaddr dst_addr in
  let sock_listen= Lwt_unix.(socket domain SOCK_STREAM 0) in
  (let addr_listen=
    let open Lwt_unix in
    match domain with
    | PF_INET-> ADDR_INET (Unix.inet_addr_any, 0)
    | PF_INET6-> ADDR_INET (Unix.inet6_addr_any, 0)
    | _-> assert false
  in
  begin%lwts
    Lwt_unix.bind sock_listen addr_listen;
    fd_write_string sock_cli
      (Msg.request_rep
        Msg.Succeeded
        (Msg.addr_of_sockaddr (Lwt_unix.getsockname sock_listen)))
      >|= ignore;
    (match%lwt
      watchdog_timeout ?timeout
        begin
          Lwt_unix.listen sock_listen 1;
          Lwt_unix.accept sock_listen;
        end
    with
    | (sock_dst, dst_addr)->
      (begin%lwts
        fd_write_string sock_cli
          (Msg.request_rep
            Msg.Succeeded
            (Msg.addr_of_sockaddr (Lwt_unix.getpeername sock_dst)))
          >|= ignore;
        pairStream ~ps1:ps sock_cli sock_dst;
      end)
      [%lwt.finally force_close sock_dst]

    | exception Watchdog Timeout-> hostUnreachable ps sock_cli);
  end)
  [%lwt.finally force_close sock_listen]


let udp ps sock_cli socksAddr_proposal=
  let%lwt addr_proposal= resolv_addr socksAddr_proposal in
  let addr_cli= Lwt_unix.getpeername sock_cli in

  let limit=
    let sa_cli= sockaddr_to_socksAddr addr_cli
    and sa_proposal= sockaddr_to_socksAddr addr_proposal in
    ref { addr= sa_cli.addr; port= sa_proposal.port }
  in
  let limit_addr= ref (socksAddr_to_sockaddr !limit) in

  let domain= Unix.domain_of_sockaddr addr_cli in
  let sock_relay= Lwt_unix.(socket domain SOCK_DGRAM 0) in
  (let addr_relay=
    let open Lwt_unix in
    if domain = PF_INET6 then
      ADDR_INET (Unix.inet6_addr_any, 0)
    else
      ADDR_INET (Unix.inet_addr_any, 0)
  in
  let%lwt relay_sockname=
    begin%lwts
      Lwt_unix.bind sock_relay addr_relay;
      return (Lwt_unix.getsockname sock_relay);
    end
  in

  let pair ()=
    let buf= Bytes.create udp_bufsize in
    let flowIn= ref 0
    and flowOut= ref 0 in
    let rec pair remotes=
      let%lwt (len, peername)=
        Lwt_unix.recvfrom sock_relay buf 0 udp_bufsize []
      in
      let peerAddr= sockaddr_to_socksAddr peername in
      let data= Caml.Bytes.(sub buf 0 len |> to_string) in

      let from_client ()=
        let handler ()=
          let%lwt msg= Parsec.parse_string MsgParser.p_udp_datagram
              data in
          let%m[@PL] ((frag, addr, data), r)= msg in
          if frag <> 0 then
            return remotes
          else
            let%lwt dst_addr= resolv_addr addr in
            let dst_sA= sockaddr_to_socksAddr dst_addr in
            let remotes= IASet.add remotes dst_sA.addr in
            let data= Caml.Bytes.of_string data in
            begin%lwts
              Lwt_unix.sendto sock_relay
                data 0 (Caml.Bytes.length data)
                [] dst_addr >|= ignore;
              return remotes;
            end
        in
        if !limit.port = 0 then
          begin
            limit:= {!limit with port= peerAddr.port};
            limit_addr:= socksAddr_to_sockaddr !limit;
            handler ()
          end
        else if !limit.port = peerAddr.port then
          handler ()
        else
          return remotes

      and from_remote ()=
        if IASet.mem remotes peerAddr.addr then
          let datagram= Caml.Bytes.of_string
            Msg.(udp_datagram 0 (addr_of_sockaddr peername) data)
          in
          Lwt_unix.sendto sock_relay
            datagram 0 (Caml.Bytes.length datagram)
            []
            !limit_addr
            >|= ignore
        else
          return ()
      in

      if !limit.addr = peerAddr.addr then
        (* from client *)
        begin
          flowOut:= !flowOut + String.length data;
          let%lwt remotes= from_client () in
          pair remotes
        end
      else
        (* from remote *)
        begin
          flowIn:= !flowIn + String.length data;
          begin%lwts
            from_remote ();
            pair remotes
          end;
        end
    in

    let pairing= pair IASet.empty in
    try%lwt
      ignore_result (watchdog_read sock_cli pairing);
      pairing
    with _-> return (!flowIn, !flowOut)
  in

  begin%lwts
    fd_write_string sock_cli
      (Msg.request_rep
        Msg.Succeeded
        (Msg.addr_of_sockaddr (Lwt_unix.getsockname sock_relay)))
      >|= ignore;
    pair ();
  end)
  [%lwt.finally force_close sock_relay]


let handshake ?timeout
  ?(auth= fun sock ps methods->
    if Caml.List.mem Msg.NoAuth methods then
      begin%lwts
        fd_write_string sock (Msg.method_rep Msg.NoAuth) >|= ignore;
        return (true, ps);
      end
    else
      begin%lwts
        cmd_notSupported ps sock >|= ignore;
        return (false, ps);
      end)
  ((sock, sockaddr):Lwt_unix.file_descr * Lwt_unix.sockaddr)
  =
  let ps= Common.initState (Common.Fd sock) in
  let%lwt r= MsgParser.p_method_req ps in
  let%m[@PL] (methods, ps)= r in

  let%lwt (pass, ps)= auth sock ps methods in

  if pass then
    try%lwt
      let%lwt r= MsgParser.p_request_req ps in
      let%m[@PL] ((cmd, addr), ps)= r in
      match cmd with
      | Cmd_connect-> connect ?timeout ps sock addr
      | Cmd_bind-> bind ?timeout ps sock addr
      | Cmd_udp-> udp ps sock addr
      | Cmd_notSupported-> cmd_notSupported ps sock
    with
    | Msg.Rep AddressTypeNotSupported-> atyp_notSupported ps sock
  else
    return (0, 0)

