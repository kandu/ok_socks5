open Core_kernel.Std
open Lwt
open Common
open Ok_parsec

let auth_userpswd sock ps user pswd=
  begin%lwts
    fd_write_string sock (Msg.auth_userpswd_req user pswd) >|= ignore;
    let%lwt r= MsgParser.p_auth_userpswd_rep ps in
    let%m[@PL] (ok, ps)= r in
    return (ok, ps)
  end

let authHandler_userpswd user pswd=
  fun sock ps meth->
    match meth with
    | Msg.NoAuth-> return ps
    | Msg.UserPswd->
      let%lwt (r, ps)= auth_userpswd sock ps user pswd in
      if r then
        return ps
      else
        fail_with "username/password invalid"
    | _-> fail_with "unsupported method"

let streamCommon ?timeout ?(methods=[Msg.NoAuth]) ?(auth= fun _ ps _-> return ps)
  ~(socks5:Lwt_unix.sockaddr) ~(dst:Msg.addr) cmd=
  let domain= Unix.domain_of_sockaddr socks5 in
  let sock= Lwt_unix.(socket domain SOCK_STREAM 0) in
  let ps= Common.initState (Common.Fd sock) in
  try%lwt
    begin%lwts
      Watchdog.watchdog_timeout ?timeout
        (Lwt_unix.connect sock socks5);

      fd_write_string sock (Msg.method_req methods) >|= ignore;
      let%lwt r= MsgParser.p_method_rep ps in
      let%m[@PL] (meth, ps)= r in

      let%lwt ps= auth sock ps meth in

      begin%lwts
        fd_write_string sock
          (Msg.request_req cmd dst)
          >|= ignore;
        let%lwt r= MsgParser.p_request_rep ps in
        let%m[@PL] ((rep, addr), ps)= r in
        if rep = Msg.Succeeded then
          return (sock, addr, ps)
        else
          Lwt.fail_with (Msg.show_rep rep)
      end;
    end
  with exn->
    begin%lwts
      force_close sock;
      Lwt.fail exn;
    end

let connect ?timeout ?(methods=[Msg.NoAuth]) ?(auth= fun _ ps _-> return ps)
  ~socks5 ~dst=
  streamCommon ?timeout ~methods ~auth ~socks5 ~dst Msg.Cmd_connect


let bind ?timeout ?(methods=[Msg.NoAuth]) ?(auth= fun _ ps _-> return ps)
  ~socks5 ~dst ~notifier=
  let%lwt (sock, addr_s, ps)=
    streamCommon ?timeout ~methods ~auth ~socks5 ~dst Msg.Cmd_bind in
  begin%lwts
    notifier addr_s;
    let%lwt r= MsgParser.p_request_rep ps in
    let%m[@PL] ((rep, addr_c), ps)= r in
    if rep = Msg.Succeeded then
      return (sock, addr_s, addr_c, ps)
    else
      Lwt.fail_with (Msg.show_rep rep)
  end

let udp_init ?timeout ?(methods=[Msg.NoAuth]) ?(auth= fun _ ps _-> return ps)
  ~socks5 ~proposal=
  let domain= Unix.domain_of_sockaddr socks5 in
  let sock= Lwt_unix.(socket domain SOCK_STREAM 0) in
  let ps= Common.initState (Common.Fd sock) in
  try%lwt
    begin%lwts
      Watchdog.watchdog_timeout ?timeout
        (Lwt_unix.connect sock socks5);

      fd_write_string sock (Msg.method_req methods) >|= ignore;
      let%lwt r= MsgParser.p_method_rep ps in
      let%m[@PL] (meth, ps)= r in

      let%lwt ps= auth sock ps meth in

      begin%lwts
        fd_write_string sock
          (Msg.request_req Msg.Cmd_udp proposal)
          >|= ignore;
        let%lwt r= MsgParser.p_request_rep ps in
        let%m[@PL] ((rep, addr), ps)= r in
        if rep = Msg.Succeeded then
          return (sock, addr, ps)
        else
          Lwt.fail_with (Msg.show_rep rep)
      end;
    end
  with exn->
    begin%lwts
      force_close sock;
      Lwt.fail exn;
    end

let udp_unpack datagram=
  let%lwt r= Parsec.parse_string MsgParser.p_udp_datagram datagram in
  let%m[@PL] ((frag, addr, data), ps)= r in
  if frag = 0 then
    return (Some (addr, data))
  else
    (* udp frag is no supported, drop the datagram silently *)
    return None

let udp_pack dst msg= Msg.udp_datagram 0 dst msg


let udp_recvfrom sock=
  let bufsize= Int.pow 2 16 in
  let buf= Bytes.create bufsize in
  let rec recv flags=
    let%lwt (len, remoteAddr)=
      Lwt_unix.recvfrom sock buf 0 bufsize flags
    in
    let datagram= Caml.Bytes.sub buf 0 len |> Caml.Bytes.to_string in
    match%lwt udp_unpack datagram with
    | Some msg-> return msg
    | None-> recv flags
  in
  recv

let udp_sendto sock relay=
  let send dst msg flags=
    let msg= udp_pack dst msg in
    let buf= Caml.Bytes.of_string msg in
    let len= String.length msg in
    Lwt_unix.send sock buf 0 len flags
  in
  begin%lwts
    Lwt_unix.connect sock relay;
    return send;
  end


let udp ?timeout ?(methods=[Msg.NoAuth]) ?(auth= fun _ ps _-> return ps)
  ~socks5 ~proposal ~local=
  let%lwt (sock_relay, addr, ps)=
    udp_init ?timeout ~methods ~auth ~socks5 ~proposal in

  let domain= Unix.domain_of_sockaddr local in
  let sock_udp= Lwt_unix.(socket domain SOCK_DGRAM 0) in

  let terminator ()=
    begin%lwts
      force_close sock_relay;
      force_close sock_udp;
    end
  in

  try%lwt
    let recv= udp_recvfrom sock_udp in

    let%lwt relay_addr= resolv_addr addr in
    let send= udp_sendto sock_udp relay_addr in

    begin%lwts
      Lwt_unix.bind sock_udp local;
      return (terminator, recv, send);
    end
  with exn->
    begin%lwts
      force_close sock_relay;
      force_close sock_udp;
      Lwt.fail exn;
    end

