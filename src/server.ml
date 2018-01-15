open Core_kernel.Std
open Lwt
open Common
open Ok_parsec


let connect ps sock_cli dst=
  let%lwt sock_dst= connect_socksAddr SOCK_STREAM dst in
  let addr= Msg.addr_of_sockaddr (Lwt_unix.getsockname sock_dst) in
  begin%lwts
    fd_write_string sock_cli (Msg.request_rep Msg.Succeeded addr)
      >|= ignore;
    pairStream ~ps1:ps sock_cli sock_dst;
  end


let bind ps sock_cli dst=
  let%lwt dst_addr= resolv_addr dst in
  let domain= Unix.domain_of_sockaddr dst_addr in
  let sock_listen= Lwt_unix.(socket domain SOCK_STREAM 0) in
  let addr_listen=
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
    let%lwt (sock_dst, dst_addr)=
      begin
        Lwt_unix.listen sock_listen 1;
        Lwt_unix.accept sock_listen;
      end
    in
    begin%lwts
      fd_write_string sock_cli
        (Msg.request_rep
          Msg.Succeeded
          (Msg.addr_of_sockaddr (Lwt_unix.getpeername sock_dst)))
        >|= ignore;
      pairStream ~ps1:ps sock_cli sock_dst;
    end;
  end


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
  let addr_relay=
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
            let remotes= IASet.add dst_sA.addr remotes in
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
      in
      let from_remote ()=
        if IASet.mem peerAddr.addr remotes then
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
    let watchdog ()=
      let bufsize= 16 in
      let buf= Caml.Bytes.create bufsize in
      let rec watchdog ()=
        let%lwt len= Lwt_unix.read sock_cli buf 0 bufsize in
        if len > 0 then
          watchdog ()
        else
          Lwt.cancel pairing |> return
      in
      watchdog ()
    in
    try%lwt
      async watchdog;
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
  end


let handshake
  ?(auth= fun sock ps methods->
    if Caml.List.mem Msg.NoAuth methods then
      begin%lwts
        fd_write_string sock (Msg.method_rep Msg.NoAuth) >|= ignore;
        return ps;
      end
    else
      Lwt.fail_with "unsupported methods")
  ((sock, sockaddr):Lwt_unix.file_descr * Lwt_unix.sockaddr)
  =
  let ps= Common.initState (Common.Fd sock) in
  let%lwt r= MsgParser.p_method_req ps in
  let%m[@PL] (methods, ps)= r in

  let%lwt ps= auth sock ps methods in

  let%lwt r= MsgParser.p_request_req ps in
  let%m[@PL] ((cmd, addr), ps)= r in
  match cmd with
  | Cmd_connect-> connect ps sock addr
  | Cmd_bind-> bind ps sock addr
  | Cmd_udp-> udp ps sock addr

