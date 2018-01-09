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
      let%m[@PL] ((req, addr, port), ps)= r in
      return (req, addr, port, ps)
    end;
  end

let connect ?(methods=[Msg.NoAuth]) ?(auth= fun _ ps _-> return ps)
  ~(socks5:Lwt_unix.sockaddr) ~(dst:socksAddr)=
  streamCommon ~methods ~auth ~socks5 ~dst


let bind ?(methods=[Msg.NoAuth]) ?(auth= fun _ ps _-> return ps)
  ~(socks5:Lwt_unix.sockaddr) ~(dst:socksAddr) ~notifier=
  let%lwt (req_s, addr_s, port_s, ps)= streamCommon ~methods ~auth ~socks5 ~dst in
  begin%lwts
    notifier req_s addr_s port_s;
    let%lwt r= MsgParser.p_request_rep ps in
    let%m[@PL] ((req_c, addr_c, port_c), ps)= r in
    return ((req_s, addr_s, port_s), (req_c, addr_c, port_c), ps)
  end

