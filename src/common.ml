open Core_kernel
open Watchdog

module PL = struct
  let parsecErr_to_string pe=
    let pos, errmsg= pe in
    sprintf "pos: %d, %s" pos errmsg

  let bind s f=
    match s with
    | Ok r-> f r
    | Error e-> failwith (parsecErr_to_string e)
end

let udp_bufsize= Int.pow 2 16

type socksAddr= {
  addr: Unix.inet_addr;
  port: int;
}

let sockaddr_to_socksAddr= function
  | Unix.ADDR_INET (ia, port)->
    {
      addr= ia;
      port;
    }
  | _-> assert false

let socksAddr_to_sockaddr sa= Unix.ADDR_INET (sa.addr, sa.port)

let fd_write_string fd str=
  Lwt_unix.write_string fd str 0 (String.length str)

let force_close fd=
  try%lwt
    Lwt_unix.close fd
  with _-> Lwt.return ()

let list_random_element l=
  let len= List.length l in
  if len > 0 then
    let i= Random.int len in
    Some (List.nth_exn l i)
  else
    None

let getIp_of_url ?timeout url=
  let%lwt addrs=
    watchdog_timeout ?timeout
      (Lwt_unix.getaddrinfo
        url
        ""
        [])
  in
  Lwt.return
    (List.filter_map addrs
      ~f:(fun addr-> match addr.Unix.ai_addr with
        | Unix.ADDR_INET (ip,_)-> Some ip
        | Unix.ADDR_UNIX _-> None)
    |> list_random_element)

let resolv_addr ?timeout addr=
  let open Lwt in
  match addr with
  | Msg.Ipv4 (ip, port)-> return (Unix.ADDR_INET (ip, port))
  | Msg.Ipv6 (ip, port)-> return (Unix.ADDR_INET (ip, port))
  | Msg.DomainName (url, port)->
    try%lwt
      let%lwt ip=
        let%lwt ip= getIp_of_url ?timeout url in
        Lwt.wrap1 (fun v-> Option.value_exn v) ip
      in
      return (Unix.ADDR_INET (ip, port))
    with _-> fail Msg.(Rep NetworkUnreachable)


let connect_sockaddr ?timeout socket_type dst=
  let domain= Unix.domain_of_sockaddr dst in
  let sock_dst= Lwt_unix.(socket domain socket_type 0) in
  begin%lwts
    Lwt_unix.connect sock_dst dst;
    (try%lwt
      begin%lwts
        watchdog_timeout ?timeout (Lwt_unix.connect sock_dst dst);
        Lwt.return sock_dst;
      end
    with e->
      begin%lwts
        force_close sock_dst;
        Lwt.fail e;
      end);
  end

let connect_socksAddr ?timeout ?connRules socket_type dst=
  watchdog_timeout ?timeout
    (let%lwt dst_addr= resolv_addr dst in
    match connRules with
    | Some connRules->
      if connRules dst dst_addr then
        connect_sockaddr socket_type dst_addr
      else
        Lwt.fail Msg.(Rep ConnectionNotAllowed)
    | None-> connect_sockaddr socket_type dst_addr)


type ioPair= {ic: Lwt_io.input_channel; oc: Lwt_io.output_channel}

let rec write_exactly fd buf pos len=
  let open Lwt in
  Lwt_unix.write fd buf pos len >>= fun out->
  if (out < len) && (len > 0) then
    write_exactly fd buf (pos+out) (len-out)
  else return ()

let pairStream ?(bufSize=Int.pow 2 14) ?ps1 ?ps2 ?ioPair1 ?ioPair2 s1 s2=
  let open Lwt in
  let cleanBuf ps ioPair=
    let%lwt ps=
      match ps with
      | None-> return Caml.Bytes.empty
      | Some ps-> Ok_parsec.Common.getBuffered ~inner:false ps >|=
          Caml.Bytes.of_string
    in
    let%lwt chan=
      match ioPair with
      | None-> return Caml.Bytes.empty
      | Some ioPair->
        begin%lwts
          Lwt_io.flush ioPair.oc;
          Lwt_io.(direct_access ioPair.ic
          (fun da->
            let len= da.da_max - da.da_ptr in
            let buf= Lwt_bytes.(to_bytes
              (extract da.da_buffer da.da_ptr len))
            in
            da.da_ptr <- da.da_ptr + len;
            return buf
          ))
        end
    in
    return (Caml.Bytes.cat ps chan)
  in
  let flowIn= ref 0.
  and flowOut= ref 0. in
  let flow remain s1 s2 record=
    let buf= Bytes.create bufSize in
    let rec flow ()=
      let%lwt readSize= Lwt_unix.read s1 buf 0 bufSize in
      if readSize > 0 then
        (record:= !record +. (Float.of_int readSize);
        Lwt_unix.write s2 buf 0 readSize >>= fun _->
        flow ())
      else
        Lwt_unix.shutdown s2 Lwt_unix.SHUTDOWN_SEND |> return
    in
    Lwt_unix.write s2 remain 0 (Bytes.length remain) >>= fun _->
    record:= !record +. (Float.of_int (Bytes.length remain));
    flow ()
  in
  let pairStream ()=
    let%lwt remain1= cleanBuf ps1 ioPair1 in
    let%lwt remain2= cleanBuf ps2 ioPair2 in
    begin%lwts
      join [flow remain1 s1 s2 flowOut; flow remain2 s2 s1 flowIn];
      return (!flowIn, !flowOut);
    end
  in
  (try%lwt
    pairStream ()
  with _-> return (!flowIn, !flowOut))
  [%lwt.finally
    begin%lwts
      force_close s1;
      force_close s2;
    end]

let pairDgram ?(filter1= fun _-> true) s1 ?(filter2= fun _-> true) s2=
  let open Lwt in
  let (sock1, addr1)= s1
  and (sock2, addr2)= s2 in
  let flowIn= ref 0.
  and flowOut= ref 0. in

  let flow s1 s2 dst filter record=
    let buf= Bytes.create udp_bufsize in
    let rec flow ()=
      let%lwt (len, peername)=
        Lwt_unix.recvfrom s1 buf 0 udp_bufsize []
      in
      record:= !record +. (Float.of_int len);
      if filter peername then
        let datagram= Caml.Bytes.(sub buf 0 len) in
        begin%lwts
          Lwt_unix.sendto s2
            datagram 0 (Caml.Bytes.length datagram)
            []
            dst
            >|= ignore;
          flow ();
        end
      else
        flow ()
    in
    flow ()
  in
  let pairStream ()=
    begin%lwts
      join [
        flow sock1 sock2 addr2 filter1 flowOut;
        flow sock2 sock1 addr1 filter2 flowIn];
      return (!flowIn, !flowOut);
    end
  in
  (try%lwt
    pairStream ()
  with _-> return (!flowIn, !flowOut))
  [%lwt.finally
    begin%lwts
      force_close sock1;
      force_close sock2;
    end]


let init ()=
  Sys.set_signal Sys.sigpipe Sys.Signal_ignore;
  Random.self_init ();
  Core_kernel.Random.self_init ()

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

