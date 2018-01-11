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

let streamCommon ?(methods=[Msg.NoAuth]) ?(auth= fun _ ps _-> return ps)
  ~(socks5:Lwt_unix.sockaddr) ~(dst:socksAddr)=
  let domain= Unix.domain_of_sockaddr socks5 in
  let sock= Lwt_unix.(socket domain SOCK_STREAM 0) in
  let ps= Common.initState (Common.Fd sock) in
  begin%lwts
    Lwt_unix.connect sock socks5;

    fd_write_string sock (Msg.method_req methods) >|= ignore;
    let%lwt r= MsgParser.p_method_rep ps in
    let%m[@PL] (meth, ps)= r in

    let%lwt ps= auth sock ps meth in

    begin%lwts
      fd_write_string sock
        (Msg.request_req Msg.Cmd_connect dst.addr dst.port)
        >|= ignore;
      let%lwt r= MsgParser.p_request_rep ps in
      let%m[@PL] ((rep, addr, port), ps)= r in
      if rep = Msg.Succeeded then
        return (sock, addr, port, ps)
      else
        Lwt.fail_with (Msg.show_rep rep)
    end;
  end

let connect ?(methods=[Msg.NoAuth]) ?(auth= fun _ ps _-> return ps)
  ~socks5 ~dst=
  streamCommon ~methods ~auth ~socks5 ~dst


let bind ?(methods=[Msg.NoAuth]) ?(auth= fun _ ps _-> return ps)
  ~socks5 ~dst ~notifier=
  let%lwt (sock, addr_s, port_s, ps)=
    streamCommon ~methods ~auth ~socks5 ~dst in
  begin%lwts
    notifier addr_s port_s;
    let%lwt r= MsgParser.p_request_rep ps in
    let%m[@PL] ((rep, addr_c, port_c), ps)= r in
    if rep = Msg.Succeeded then
      return (sock, (addr_s, port_s), (addr_c, port_c), ps)
    else
      Lwt.fail_with (Msg.show_rep rep)
  end

let udp_init ?(methods=[Msg.NoAuth]) ?(auth= fun _ ps _-> return ps)
  ~socks5 ~local=
  let domain= Unix.domain_of_sockaddr socks5 in
  let sock= Lwt_unix.(socket domain SOCK_STREAM 0) in
  let ps= Common.initState (Common.Fd sock) in
  begin%lwts
    Lwt_unix.connect sock socks5;

    fd_write_string sock (Msg.method_req methods) >|= ignore;
    let%lwt r= MsgParser.p_method_rep ps in
    let%m[@PL] (meth, ps)= r in

    let%lwt ps= auth sock ps meth in

    begin%lwts
      fd_write_string sock
        (Msg.request_req Msg.Cmd_udp local.addr local.port)
        >|= ignore;
      let%lwt r= MsgParser.p_request_rep ps in
      let%m[@PL] ((rep, addr, port), ps)= r in
      if rep = Msg.Succeeded then
        return (sock, addr, port, ps)
      else
        Lwt.fail_with (Msg.show_rep rep)
    end;
  end

let udp_recvfrom sock flags=
  let bufsize= Int.pow 2 16 in
  let buf= Bytes.create bufsize in
  let rec recv ()=
    let%lwt (len, remoteAddr)=
      Lwt_unix.recvfrom sock buf 0 bufsize flags
    in
    let datagram= Caml.Bytes.sub buf 0 len |> Caml.Bytes.to_string in
    let%lwt r= Parsec.parse_string MsgParser.p_udp_datagram datagram in
    let%m[@PL] ((frag, addr, port, data), ps)= r in
    if frag = 0 then
      return (addr, port, data)
    else
      (* udp frag is no supported, drop the datagram silently *)
      recv ()
  in
  recv

let udp_sendto sock relay flags=
  let send msg=
    let buf= Caml.Bytes.of_string msg in
    let len= String.length msg in
    Lwt_unix.sendto sock buf 0 len flags relay
  in
  send

