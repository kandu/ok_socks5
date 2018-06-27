open Core_kernel.Std [@@ocaml.warning "-3"]

let int16_to_net a= sprintf "%c%c"
  (a lsr 8 |> char_of_int)
  (a land 0xff |> char_of_int)

let ver_socks= '\x05'
let ver_auth_userpswd= '\x01'

type meth=
  | NoAuth
  | Gssapi
  | UserPswd
  | NoAcpt

let meth_to_bin meth=
  char_of_int
    (match meth with
    | NoAuth-> 0
    | Gssapi-> 1
    | UserPswd-> 2
    | NoAcpt-> 0xff)

let meth_of_bin bin=
  match bin with
  | 0-> NoAuth
  | 1-> Gssapi
  | 2-> UserPswd
  | 0xff-> NoAcpt
  | _-> sprintf "unkown method %d" bin |> failwith

type rep=
  | Succeeded
  | GeneralServerFailure
  | ConnectionNotAllowed
  | NetworkUnreachable
  | HostUnreachable
  | ConnectionRefused
  | TtlExpired
  | CommandNotSupported
  | AddressTypeNotSupported
  | Unassigned
  [@@deriving show]

exception Rep of rep


type cmd=
  | Cmd_connect
  | Cmd_bind
  | Cmd_udp
  | Cmd_notSupported
  [@@deriving show]

let cmd_to_bin cmd=
  char_of_int
    (match cmd with
    | Cmd_connect-> 1
    | Cmd_bind-> 2
    | Cmd_udp-> 3
    | Cmd_notSupported-> raise (Rep CommandNotSupported)
    )

type atyp=
  | Atyp_ipv4
  | Atyp_domainName
  | Atyp_ipv6
  | Atyp_notSupported
 
let atyp_to_bin atyp=
  char_of_int
    (match atyp with
    | Atyp_ipv4-> 1
    | Atyp_domainName-> 3
    | Atyp_ipv6-> 4
    | Atyp_notSupported-> raise (Rep AddressTypeNotSupported)
    )

type addr=
  | Ipv4 of Unix.inet_addr * int
  | Ipv6 of Unix.inet_addr * int
  | DomainName of string * int

let anyAddr4= Ipv4 (Unix.inet_addr_any, 0)
let anyAddr6= Ipv6 (Unix.inet6_addr_any, 0)

type port= int

let get_port_of_addr addr=
  match addr with
  | Ipv4 (_, port)-> port
  | Ipv6 (_, port)-> port
  | DomainName (_, port)-> port

let addr_of_sockaddr sa=
  match sa with
  | Unix.ADDR_UNIX dm-> failwith "unix domain is not supported"
  | Unix.ADDR_INET (ia, port)->
    match Unix.domain_of_sockaddr sa with
    | Unix.PF_INET-> Ipv4 (ia, port)
    | Unix.PF_INET6-> Ipv6 (ia, port)
    | Unix.PF_UNIX-> failwith "unix domain is not supported"

let inet_addr_of_bin (bin: string)= (Obj.magic bin: Unix.inet_addr)
let inet_addr_to_bin (addr: Unix.inet_addr)= (Obj.magic addr: string)

let addr_to_bin addr=
  match addr with
  | Ipv4 (ia, port)-> sprintf "%c%s%s"
    (atyp_to_bin Atyp_ipv4)
    (inet_addr_to_bin ia)
    (int16_to_net port)
  | Ipv6 (ia, port)-> sprintf "%c%s%s"
    (atyp_to_bin Atyp_ipv6)
    (inet_addr_to_bin ia)
    (int16_to_net port)
  | DomainName (dn, port)-> sprintf "%c%c%s%s"
    (atyp_to_bin Atyp_domainName)
    (String.length dn |> char_of_int)
    dn
    (int16_to_net port)

let rep_to_bin rep=
  char_of_int
    (match rep with
    | Succeeded-> 0
    | GeneralServerFailure-> 1
    | ConnectionNotAllowed-> 2
    | NetworkUnreachable-> 3
    | HostUnreachable-> 4
    | ConnectionRefused-> 5
    | TtlExpired-> 6
    | CommandNotSupported-> 7
    | AddressTypeNotSupported-> 8
    | Unassigned-> 9)


let method_req methods=
  let n= min 255 (List.length methods) in
  let methods= List.take methods n in
  let methods= methods
    |> List.map ~f:meth_to_bin
    |> String.of_char_list
  in
  sprintf "%c%c%s" ver_socks (char_of_int n) methods

let method_rep meth= sprintf "%c%c" ver_socks (meth_to_bin meth)

let request_req cmd addr=
  sprintf "%c%c\x00%s"
    ver_socks
    (cmd_to_bin cmd)
    (addr_to_bin addr)

let request_rep rep addr=
  sprintf "%c%c\x00%s"
    ver_socks
    (rep_to_bin rep)
    (addr_to_bin addr)

let udp_datagram frag addr data=
  sprintf "\x00\x00%c%s%s"
    (char_of_int frag)
    (addr_to_bin addr)
    data

let auth_userpswd_req user pswd=
  let ulen= min 255 (String.length user)
  and plen= min 255 (String.length pswd) in
  let user= String.sub user ~pos:0 ~len:ulen
  and pswd= String.sub pswd ~pos:0 ~len:plen in
  sprintf "%c%c%s%c%s"
    ver_auth_userpswd
    (char_of_int ulen)
    user
    (char_of_int plen)
    pswd

let auth_userpswd_rep status=
  let status= char_of_int
    (match status with
    | true-> 0
    | false-> 1)
  in
  sprintf "%c%c"
    ver_auth_userpswd
    status

