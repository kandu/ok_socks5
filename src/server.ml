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
    pairStream sock_cli sock_dst;
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
  | Cmd_bind-> return (0, 0)
  | Cmd_udp-> return (0, 0)

