open Core.Std [@@ocaml.warning "-3"]
open Fn
open Lwt
open Ok_socks5
open Common
open Printf

let pp_sexp_hum= Format.asprintf "%a" Sexplib.Sexp.pp_hum

let write sock str=
  Lwt_unix.write_string sock str 0 (String.length str) >|= ignore

let getInetHostName sock=
  match Lwt_unix.getsockname sock with
  | Unix.ADDR_INET (addr, port)-> (addr, port)
  | Unix.ADDR_UNIX _-> failwith "inet expected"


let s f=
  let sock= Lwt_unix.(socket PF_INET SOCK_STREAM 0) in
  let addr= Unix.(ADDR_INET (Inet_addr.localhost, 9668)) in
  begin%lwts
    Lwt_unix.connect sock addr;
    let%lwt (sock_listen, addr_sock, addr_remote, ps)=
      Client.bind
        ~socks5:Unix.(ADDR_INET (Inet_addr.localhost, 9667))
        ~dst:Msg.anyAddr4
        ~notifier:(fun addr->
          let port= Msg.get_port_of_addr addr in
          write sock (string_of_int port)
          )
        ()
    in
    let buf= Bytes.create 1024 in
    let%lwt len= Lwt_unix.read sock_listen buf 0 1024 in
    Lwt_io.print Caml.Bytes.(sub buf 0 len |> to_string)
  end

let ()=
  Common.init ();
  Lwt_main.run @@ s ()
