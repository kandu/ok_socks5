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
  ~(socks5:Lwt_unix.sockaddr) ~(socksAddr:socksAddr)=
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
        (Msg.request_req Msg.Cmd_connect socksAddr.addr socksAddr.port)
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
  streamCommon ~methods ~auth ~socks5 ~socksAddr:dst


let bind ?(methods=[Msg.NoAuth]) ?(auth= fun _ ps _-> return ps)
  ~socks5 ~listen ~notifier=
  let%lwt (sock, addr_s, port_s, ps)=
    streamCommon ~methods ~auth ~socks5 ~socksAddr:listen in
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

