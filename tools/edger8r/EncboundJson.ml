(* Small JSON reader for generator configuration and Clang's record AST.
 * EDL is parsed exclusively by Intel's parser. No external OCaml packages. *)
type t = Object of (string * t) list | Array of t list | String of string
       | Number of string | Bool of bool | Null
let fail s = failwith ("ENCBound JSON: " ^ s)
let read_file p = let c = open_in_bin p in
  Fun.protect ~finally:(fun () -> close_in c)
    (fun () -> really_input_string c (in_channel_length c))
let parse s =
  let i = ref 0 and n = String.length s in
  let rec space () = while !i < n && List.mem s.[!i] [' '; '\n'; '\r'; '\t'] do incr i done
  and expect c = if !i >= n || s.[!i] <> c then fail "unexpected token" else incr i
  and string () =
    expect '"'; let b = Buffer.create 32 in
    let utf8 v =
      let add x = Buffer.add_char b (Char.chr x) in
      if v < 128 then add v else if v < 2048 then (add (192 lor (v lsr 6)); add (128 lor (v land 63)))
      else if v < 65536 then (add (224 lor (v lsr 12)); add (128 lor ((v lsr 6) land 63)); add (128 lor (v land 63)))
      else (add (240 lor (v lsr 18)); add (128 lor ((v lsr 12) land 63)); add (128 lor ((v lsr 6) land 63)); add (128 lor (v land 63))) in
    let hex () = if !i + 4 > n then fail "short unicode escape";
      let v = try int_of_string ("0x" ^ String.sub s !i 4) with _ -> fail "bad unicode escape" in i := !i + 4; v in
    let rec loop () =
      if !i >= n then fail "unterminated string";
      let c = s.[!i] in incr i;
      if c = '"' then Buffer.contents b else (
        if c = '\\' then (
          if !i >= n then fail "short escape";
          let e = s.[!i] in incr i;
          match e with
          | '"' | '\\' | '/' -> Buffer.add_char b e
          | 'n' -> Buffer.add_char b '\n' | 'r' -> Buffer.add_char b '\r'
          | 't' -> Buffer.add_char b '\t' | 'b' -> Buffer.add_char b '\b'
          | 'f' -> Buffer.add_char b (Char.chr 12)
          | 'u' -> let v = hex () in
            if v >= 0xd800 && v <= 0xdbff then (
              expect '\\'; expect 'u'; let w = hex () in
              if w < 0xdc00 || w > 0xdfff then fail "bad surrogate";
              utf8 (0x10000 + ((v - 0xd800) lsl 10) + w - 0xdc00))
            else if v >= 0xdc00 && v <= 0xdfff then fail "bad surrogate" else utf8 v
          | _ -> fail "unknown escape")
        else if Char.code c < 32 then fail "control character" else Buffer.add_char b c;
        loop ()) in loop ()
  and value () =
    space (); if !i >= n then fail "missing value";
    match s.[!i] with
    | '"' -> String (string ())
    | '{' -> incr i; space ();
      let rec fields acc =
        space (); let k = string () in
        if List.mem_assoc k acc then fail ("duplicate key " ^ k);
        space (); expect ':'; let v = value () in space ();
        if !i < n && s.[!i] = ',' then (incr i; fields ((k,v)::acc))
        else (expect '}'; Object (List.rev ((k,v)::acc))) in
      if !i < n && s.[!i] = '}' then (incr i; Object []) else fields []
    | '[' -> incr i; space ();
      let rec items acc = let v = value () in space ();
        if !i < n && s.[!i] = ',' then (incr i; items (v::acc))
        else (expect ']'; Array (List.rev (v::acc))) in
      if !i < n && s.[!i] = ']' then (incr i; Array []) else items []
    | 't' | 'f' | 'n' ->
      let literal, v = match s.[!i] with 't' -> "true", Bool true | 'f' -> "false", Bool false | _ -> "null", Null in
      let l = String.length literal in
      if !i+l > n || String.sub s !i l <> literal then fail "bad literal";
      i := !i+l; v
    | '-' | '0'..'9' ->
      let start = !i in
      if s.[!i] = '-' then incr i;
      if !i >= n then fail "bad number";
      if s.[!i] = '0' then incr i else (
        if s.[!i] < '1' || s.[!i] > '9' then fail "bad number";
        while !i < n && s.[!i] >= '0' && s.[!i] <= '9' do incr i done);
      let digits () = let start = !i in
        while !i < n && s.[!i] >= '0' && s.[!i] <= '9' do incr i done;
        if start = !i then fail "bad number" in
      if !i < n && s.[!i] = '.' then (incr i; digits ());
      if !i < n && (s.[!i] = 'e' || s.[!i] = 'E') then (
        incr i; if !i < n && (s.[!i] = '+' || s.[!i] = '-') then incr i; digits ());
      Number (String.sub s start (!i-start))
    | _ -> fail "unexpected value"
  in let v = value () in space (); if !i <> n then fail "trailing content"; v
let load p = parse (read_file p)
let obj = function Object v -> v | _ -> fail "expected object"
let arr = function Array v -> v | _ -> fail "expected array"
let str = function String v -> v | _ -> fail "expected string"
let get k = function Object xs -> (try List.assoc k xs with Not_found -> Null) | _ -> Null
let quote s = let b = Buffer.create 32 in Buffer.add_char b '"';
  String.iter (fun c -> match c with
    | '"' -> Buffer.add_string b "\\\"" | '\\' -> Buffer.add_string b "\\\\"
    | c when Char.code c < 32 -> Buffer.add_string b (Printf.sprintf "\\u%04x" (Char.code c))
    | c -> Buffer.add_char b c) s; Buffer.add_char b '"'; Buffer.contents b
let rec show = function
  | Object xs -> "{" ^ String.concat "," (List.map (fun (k,v) -> quote k ^ ":" ^ show v) xs) ^ "}"
  | Array xs -> "[" ^ String.concat "," (List.map show xs) ^ "]"
  | String s -> quote s | Number n -> n | Bool true -> "true" | Bool false -> "false" | Null -> "null"
