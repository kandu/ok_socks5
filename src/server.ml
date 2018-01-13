open Core_kernel.Std
open Lwt
open Common
open Ok_parsec


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
  let%m[@PL] ((cmd, addr, port), ps)= r in
  match cmd with
  | Cmd_connect-> return ()
  | Cmd_bind-> return ()
  | Cmd_udp-> return ()

