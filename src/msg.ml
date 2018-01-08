open Core_kernel.Std

let int16_to_net a= sprintf "%c%c"
  (a lsr 8 |> char_of_int)
  (a land 0xff |> char_of_int)

let ver_socks= '5'
let ver_auth_userpswd= '1'

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

type cmd=
  | Cmd_connect
  | Cmd_bind
  | Cmd_udp
  [@@deriving show, sexp]

let cmd_to_bin cmd=
  char_of_int
    (match cmd with
    | Cmd_connect-> 1
    | Cmd_bind-> 2
    | Cmd_udp-> 3)

type atyp=
  | Atyp_ipv4
  | Atyp_domainName
  | Atyp_ipv6
 
let atyp_to_bin atyp=
  char_of_int
    (match atyp with
    | Atyp_ipv4-> 1
    | Atyp_domainName-> 3
    | Atyp_ipv6-> 4
    )

type addr=
  | Ipv4 of Unix.inet_addr
  | Ipv6 of Unix.inet_addr
  | DomainName of string

type port= int

let addr_of_inetAddr ia=
  match Unix.domain_of_sockaddr (Unix.ADDR_INET (ia,0)) with
  | Unix.PF_INET-> Ipv4 ia
  | Unix.PF_INET6-> Ipv6 ia
  | Unix.PF_UNIX-> failwith "unix domain is not supported"

let inet_addr_of_bin (bin: string)= (Obj.magic bin: Unix.inet_addr)
let inet_addr_to_bin (addr: Unix.inet_addr)= (Obj.magic addr: string)

let addr_to_bin addr=
  match addr with
  | Ipv4 al-> sprintf "%c%s"
    (atyp_to_bin Atyp_ipv4)
    (inet_addr_to_bin al)
  | Ipv6 al-> sprintf "%c%s"
    (atyp_to_bin Atyp_ipv6)
    (inet_addr_to_bin al)
  | DomainName dn-> sprintf "%c%c%s"
    (atyp_to_bin Atyp_domainName)
    (String.length dn |> char_of_int)
    dn

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


let rep_request rep addr port=
  sprintf "%c%c\x00%s%s"
    ver_socks
    (rep_to_bin rep)
    (addr_to_bin addr)
    (int16_to_net port)

let rep_request_inet rep (inet:Unix.inet_addr) port=
  let inet:string= Obj.magic inet in
  let atyp= if String.length inet = 16 then 4 else 1 in
  sprintf "%c%c\x00%c%s%s"
    ver_socks
    (rep_to_bin rep)
    (char_of_int atyp)
    inet
    (int16_to_net port)

let method_req methods=
  let n= min 255 (List.length methods) in
  let methods= List.take methods n in
  let methods= methods
    |> List.map ~f:meth_to_bin
    |> String.of_char_list
  in
  sprintf "%c%c%s" ver_socks (char_of_int n) methods

let method_rep meth= sprintf "%c%c" ver_socks (meth_to_bin meth)

let request_req cmd addr port=
  sprintf "%c%c\x00%s%s"
    ver_socks
    (cmd_to_bin cmd)
    (addr_to_bin addr)
    (int16_to_net port)

let request_rep rep addr port=
  sprintf "%c%c\x00%s%s"
    ver_socks
    (rep_to_bin rep)
    (addr_to_bin addr)
    (int16_to_net port)

let udp_datagram frag addr port data=
  sprintf "\x00\x00%c%s%s%s"
    (char_of_int frag)
    (addr_to_bin addr)
    (int16_to_net port)
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

