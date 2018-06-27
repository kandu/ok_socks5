open Core.Std [@@ocaml.warning "-3"]
open Fn
open Lwt
open Ok_socks5
open Common
open Printf

let buf= Bytes.create 1024

let read_s sock=
  let%lwt len= Lwt_unix.read sock buf 0 1024 in
  return (Caml.Bytes.sub_string buf 0 len)

let write_s sock s=
  Lwt_unix.write_string sock s 0 (String.length s) >|= ignore

let pp_sexp_hum= Format.asprintf "%a" Sexplib.Sexp.pp_hum

let getSockAddr name=
  match name with
  | Unix.ADDR_INET (addr, port)-> (addr, port)
  | Unix.ADDR_UNIX _-> failwith "inet expected"


let sa_to_string (addr, port)= sprintf "(%s, %d)"
  (Unix.Inet_addr.to_string addr)
  port

let listen server f=
  let rec wait sock=
    let%lwt (fd, peername)= Lwt_unix.accept sock in
    ignore_result @@
      (try%lwt
        f fd peername;
      with e-> Lwt_io.eprintl (Exn.to_string_mach e))
      [%lwt.finally force_close fd];
    wait sock
  in
  wait server

let comm addr=
  let sock= Lwt_unix.(socket PF_INET SOCK_STREAM 0) in
  begin%lwts
    Lwt_io.printf "socks5 bind addr: %s\n" (sa_to_string (getSockAddr addr));
    Lwt_unix.connect sock addr;
    write_s sock "from server\n";
    Lwt_unix.close sock;
  end

let f sock peername=
  begin%lwts
    Lwt_io.printf "hostname: %s\n" (sa_to_string (getSockAddr (Lwt_unix.getsockname sock)));
    Lwt_io.printf "peername: %s\n" (sa_to_string (getSockAddr peername));
    let%lwt port= read_s sock >|= int_of_string in
    let addr= Unix.(ADDR_INET (Inet_addr.localhost, port)) in
    begin%lwts
      comm addr;
      Lwt_unix.close sock;
    end
  end


let s f=
  let sock_listen= Lwt_unix.(socket PF_INET SOCK_STREAM 0) in
  Lwt_unix.(setsockopt sock_listen SO_REUSEADDR true);
  begin%lwts
    Lwt_unix.bind sock_listen Unix.(ADDR_INET (Inet_addr.bind_any, 9668));
    let sockname= Lwt_unix.getsockname sock_listen in
    Lwt_unix.listen sock_listen 20;
    begin%lwts
      Lwt_io.printl (Unix.sexp_of_sockaddr sockname |> pp_sexp_hum);
      listen sock_listen f;
    end
  end

let ()=
  Common.init ();
  Lwt_main.run @@ s f

