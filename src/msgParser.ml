open Core_kernel.Std
open Ok_parsec
open Parsec
open Msg

let ver_socks= char '\x05'
let meth_num= int8
let meth= int8 |>> meth_of_bin

let rsv= char '\x00'

let plen8Str= int8
  >>= fun len-> times len any
  |>> String.of_char_list

let plen16Str= int16
  >>= fun len-> times len any
  |>> String.of_char_list

let methods n= times n meth

let cmd_connect= char '\x01' >>$ Cmd_connect
let cmd_bind= char '\x02' >>$ Cmd_bind
let cmd_udp= char '\x03' >>$ Cmd_udp
let cmd=
  cmd_connect
  <|> cmd_bind
  <|> cmd_udp


let rep_succeeded=
  char (rep_to_bin Succeeded)
  >>$ Succeeded
let rep_generalServerFailure=
  char (rep_to_bin GeneralServerFailure)
  >>$ GeneralServerFailure
let rep_connectionNotAllowed=
  char (rep_to_bin ConnectionNotAllowed)
  >>$ ConnectionNotAllowed
let rep_networkUnreachable=
  char (rep_to_bin NetworkUnreachable)
  >>$ NetworkUnreachable
let rep_hostUnreachable=
  char (rep_to_bin HostUnreachable)
  >>$ HostUnreachable
let rep_connectionRefused=
  char (rep_to_bin ConnectionRefused)
  >>$ ConnectionRefused
let rep_ttlExpired=
  char (rep_to_bin TtlExpired)
  >>$ TtlExpired
let rep_commandNotSupported=
  char (rep_to_bin CommandNotSupported)
  >>$ CommandNotSupported
let rep_addressTypeNotSupported=
  char (rep_to_bin AddressTypeNotSupported)
  >>$ AddressTypeNotSupported
let rep_unassigned=
  char (rep_to_bin Unassigned)
  >>$ Unassigned

let rep=
  rep_succeeded
  <|> rep_generalServerFailure
  <|> rep_connectionNotAllowed
  <|> rep_networkUnreachable
  <|> rep_hostUnreachable
  <|> rep_connectionRefused
  <|> rep_ttlExpired
  <|> rep_commandNotSupported
  <|> rep_addressTypeNotSupported
  <|> rep_unassigned


let atyp_ipv4= char '\x01' >>$ Atyp_ipv4
let atyp_domainName= char '\x03' >>$ Atyp_domainName
let atyp_ipv6= char '\x04' >>$ Atyp_ipv6
let atyp= atyp_ipv4
  <|> atyp_domainName
  <|> atyp_ipv6

(* let dstAddr_ipv4= times 4 int8 *)
let dstAddr_ipv4= times 4 any
  |>> String.of_char_list
  |>> inet_addr_of_bin

(* let dstAddr_ipv6= times 8 int16_net *)
let dstAddr_ipv6= times 16 any
  |>> String.of_char_list
  |>> inet_addr_of_bin

let dstAddr_domain= int8
  >>= fun len-> times len any
  |>> String.of_char_list

let dstPort= int16_net

let addr=
  atyp >>= function
    | Atyp_ipv4-> dstAddr_ipv4
      >>= fun addr-> dstPort
      >>= fun port->
      return (Ipv4 (addr, port))
    | Atyp_ipv6-> dstAddr_ipv6
      >>= fun addr-> dstPort
      >>= fun port->
      return (Ipv6 (addr, port))
    | Atyp_domainName-> dstAddr_domain |>> fun addr-> DomainName addr


(**************************************************************************)

(* auth method *)
let ver_auth_userpswd= char '\x01'

(**************************************************************************)

let p_method_req= ver_socks >> meth_num >>= methods
let p_method_rep= ver_socks >> meth


let p_request_req= ver_socks >> cmd
  >>= fun cmd-> rsv >> addr
  >>= fun addr-> dstPort
  >>= fun port->
    return (cmd, addr, port)

let p_request_rep= ver_socks >> rep
  >>= fun rep-> rsv >> addr
  >>= fun addr-> dstPort
  >>= fun port->
    return (rep, addr, port)


let p_udp_datagram= rsv >> rsv >> int8
  >>= fun frag-> addr
  >>= fun addr-> dstPort
  >>= fun port-> many any |>> String.of_char_list
  >>= fun data->
  return (frag, addr, port, data)


(* auth method *)

let p_auth_userpswd_req= ver_auth_userpswd >> plen8Str
  >>= fun user-> plen8Str
  >>= fun pswd->
  return (user, pswd)

let p_auth_userpswd_rep= ver_auth_userpswd >> int8 |>> ((=) 0)

