open Lwt

type watchdog=
  | Timeout
  | Fd_read

exception Watchdog of watchdog

let watchdog_timeout ?timeout thread=
  match timeout with
  | Some timeout->
    let watchdog=
      begin%lwts
        Lwt_unix.sleep timeout;
        fail (Watchdog Timeout)
      end
    in
    pick [
      watchdog;
      thread;
    ]
  | None-> thread

let watchdog_read fd thread=
  (** cancel thread when fd closed/eof *)
  let bufsize= 16 in
  let buf= Bytes.create bufsize in
  let rec watch ()=
    let%lwt len= Lwt_unix.read fd buf 0 bufsize in
    if len > 0 then
      watch ()
    else
      return ()
  in
  let watchdog=
    begin%lwts
      (try%lwt watch () with _-> return ());
      fail (Watchdog Fd_read);
    end
  in
  pick [
    watchdog;
    thread;
  ]

