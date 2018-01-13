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


let list_random_element l=
  let len= List.length l in
  if len > 0 then
    let i= Random.int len in
    Some (List.nth_exn l i)
  else
    None

let getIp_of_url url=
  let%lwt addrs= Lwt_unix.getaddrinfo
    url
    ""
    []
  in
  Lwt.return
    (List.filter_map addrs
      ~f:(fun addr-> match addr.Unix.ai_addr with
        | Unix.ADDR_INET (ip,_)-> Some ip
        | Unix.ADDR_UNIX _-> None)
    |> list_random_element)

let getIp_of_addr addr=
  let open Lwt in
  match addr with
  | Msg.Ipv4 ip-> return ip
  | Msg.Ipv6 ip-> return ip
  | Msg.DomainName url->
    let%lwt ip= getIp_of_url url in
    Lwt.wrap1 (fun v-> Option.value_exn v) ip


let connect_sockaddr socket_type dst=
  let domain= Unix.domain_of_sockaddr dst in
  let sock_dst= Lwt_unix.(socket domain socket_type 0) in
  begin%lwts
    Lwt_unix.connect sock_dst dst;
    Lwt.return sock_dst;
  end

let connect_socksAddr socket_type dst=
  let (addr, port)= dst in
  let%lwt dst_ip= getIp_of_addr addr in
  let dst_sockaddr= Unix.ADDR_INET (dst_ip, port) in
  connect_sockaddr socket_type dst_sockaddr

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

