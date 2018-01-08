open Core_kernel.Std

module PL = struct
  let parsecErr_to_string pe=
    let pos, errmsg= pe in
    sprintf "pos: %d, %s" pos errmsg

  let bind s f=
    match s with
    | Ok r-> f r
    | Error e-> failwith (parsecErr_to_string e)
end

type socksAddr= {
  addr: Msg.addr;
  port: Msg.port;
}

let fd_write_string fd str=
  Lwt_unix.write_string fd str 0 (String.length str)

open Ctypes
open Foreign

module Stub = struct

  let htonl=
    foreign "htonl"
    (uint32_t @-> returning uint32_t)

  let htons=
    foreign "htons"
    (uint16_t @-> returning uint16_t)

  let ntohl=
    foreign "ntohl"
    (uint32_t @-> returning uint32_t)

  let ntohs=
    foreign "ntohs"
    (uint16_t @-> returning uint16_t)

end

let htons h= Unsigned.UInt16.to_int
  (Stub.htons (Unsigned.UInt16.of_int h))
let ntohs n= Unsigned.UInt16.to_int
  (Stub.ntohs (Unsigned.UInt16.of_int n))

let htonl h= Unsigned.UInt32.to_int64
  (Stub.htonl (Unsigned.UInt32.of_int64 h))
let ntohl n= Unsigned.UInt32.to_int64
  (Stub.ntohl (Unsigned.UInt32.of_int64 n))

