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
      pairStream sock_cli sock_dst;
    end;
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
  | Cmd_udp-> return (0, 0)

