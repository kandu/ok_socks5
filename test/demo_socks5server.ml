open Core.Std [@@ocaml.warning "-3"]
open Fn
open Lwt
open Ok_socks5
open Common

let pp_sexp_hum= Format.asprintf "%a" Sexplib.Sexp.pp_hum

let listen server f=
  let rec wait sock=
    let%lwt (fd, _)= Lwt_unix.accept sock in
    ignore_result @@
      (try%lwt
        f fd;
      with e-> Lwt_io.eprintl (Exn.to_string_mach e))
      [%lwt.finally force_close fd];
    wait sock
  in
  wait server

let s f=
  let sock_listen= Lwt_unix.(socket PF_INET SOCK_STREAM 0) in
  Lwt_unix.(setsockopt sock_listen SO_REUSEADDR true);
  begin%lwts
    Lwt_unix.bind sock_listen Unix.(ADDR_INET (Inet_addr.bind_any, 9667));
    let sockname= Lwt_unix.getsockname sock_listen in
    Lwt_unix.listen sock_listen 20;
    begin%lwts
      Lwt_io.printl (Unix.sexp_of_sockaddr sockname |> pp_sexp_hum);
      listen sock_listen f;
    end
  end

let f sock=
  let%lwt (flowIn, flowOut)= Server.handshake sock in
  Lwt_io.printf "%s: %f, %f\n"
    (Unix.sexp_of_sockaddr (Lwt_unix.getpeername sock) |> pp_sexp_hum)
    flowIn
    flowOut

let ()=
  Common.init ();
  Lwt_main.run @@ s f

