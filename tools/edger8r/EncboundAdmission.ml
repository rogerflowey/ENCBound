(* Application-interface admission on Intel's AST, before any bridge emission.
 * Generated bridges remain trusted. SDK imports retain their raw ABI. *)
open Ast
module J = EncboundJson
let fail s = failwith ("ENCBound: " ^ s)
let getenv k fallback = try Sys.getenv k with Not_found -> fallback
let enabled = getenv "ENCBOUND_BRIDGE_CONFIG" "" <> ""
let config = lazy (J.load (Sys.getenv "ENCBOUND_BRIDGE_CONFIG"))
let profile = getenv "ENCBOUND_BRIDGE_PROFILE" ""
let cxx_eh = getenv "ENCBOUND_BRIDGE_CXX_EH" "0" = "1"
let ecalls = ref [] and ocalls = ref [] and sdk_names = ref []
let sdk_ecalls = ref []
let sdk_ecall_origins = ref []
let errno_ocalls = ref []
let errno_symbols = ["__encbound_app_errno_location"; "__encbound_app_errno_store"]
let dependencies = ref [] and imported = ref []
let application_tnames = ref [] and application_unames = ref []
let import_origins = ref []
let remember p = let p = Unix.realpath p in
  if not (List.mem p !dependencies) then dependencies := p :: !dependencies
let write p s = let c = open_out_bin p in
  Fun.protect ~finally:(fun () -> close_out c) (fun () -> output_string c s)
let run_capture args =
  let out = Filename.temp_file "encbound-tool-" ".out" in
  Fun.protect ~finally:(fun () -> Sys.remove out) (fun () ->
    let fd = Unix.openfile out [Unix.O_WRONLY; Unix.O_TRUNC] 0o600 in
    let pid = Unix.create_process (List.hd args) (Array.of_list args) Unix.stdin fd Unix.stderr in
    Unix.close fd;
    (match snd (Unix.waitpid [] pid) with Unix.WEXITED 0 -> () | _ -> fail ("tool failed: " ^ List.hd args));
    J.read_file out)
let sha256 p = let line = run_capture ["sha256sum"; "--"; p] in String.sub line 0 64
let names ec = List.map (fun f -> f.tf_fdecl.fname) ec.tfunc_decls @
  List.map (fun f -> f.uf_fdecl.fname) ec.ufunc_decls
let observe_application ec =
  application_tnames := List.sort_uniq String.compare
    (!application_tnames @ List.map (fun f -> f.tf_fdecl.fname) ec.tfunc_decls);
  application_unames := List.sort_uniq String.compare
    (!application_unames @ List.map (fun f -> f.uf_fdecl.fname) ec.ufunc_decls)
let observe_import name path ec = if enabled then (
  let policies = J.get "sdk_only_imports" (Lazy.force config) |> J.obj in
  let path = Unix.realpath path in
  let hash = sha256 path in
  let domain = match List.assoc_opt name policies with
    | None -> observe_application ec; "application"
    | Some p ->
      let declared = J.get "symbols" p |> J.arr |> List.map J.str |> List.sort_uniq String.compare in
      if J.get "domain" p <> J.String "sdk" || J.get "sha256" p <> J.String hash ||
         declared <> List.sort_uniq String.compare (names ec) || ec.import_exprs <> []
      then fail ("SDK import identity, domain or symbol set changed: " ^ name);
      if ec.tfunc_decls <> [] then (
        (* A workload policy cannot promote arbitrary enclave code to TRUSTED.
         * Only exact, separately pinned SDK entry contracts have a raw lane. *)
        let contracts_path = Sys.getenv "ENCBOUND_BRIDGE_SDK_ECALLS" in
        remember contracts_path;
        let contract = J.get name (J.load contracts_path) in
        if contract = J.Null || J.get "sha256" contract <> J.String hash ||
           (J.get "symbols" contract |> J.arr |> List.map J.str |> List.sort_uniq String.compare) <> declared ||
           ec.ufunc_decls <> [] || List.exists (fun f -> f.tf_is_priv || f.tf_is_switchless) ec.tfunc_decls
        then fail ("SDK import identity or unsupported trusted-entry contract: " ^ name);
        if not (List.mem name !sdk_ecall_origins) then sdk_ecall_origins := name :: !sdk_ecall_origins);
      imported := name :: !imported;
      sdk_names := List.sort_uniq String.compare (!sdk_names @ names ec);
      "sdk" in
  let strings xs = J.Array (List.map (fun s -> J.String s) xs) in
  let origin = J.Object ["name",J.String name;"path",J.String path;
    "sha256",J.String hash;"domain",J.String domain;
    "declared_ecalls",strings (List.map (fun f -> f.tf_fdecl.fname) ec.tfunc_decls);
    "declared_ocalls",strings (List.map (fun f -> f.uf_fdecl.fname) ec.ufunc_decls)] in
  if not (List.mem origin !import_origins) then import_origins := origin :: !import_origins;
  remember path)

(* Clang classifies actual transport types. Only value-record adapters need
 * modeled field layouts, independently checked against the bridge header. *)
let scalar_layout = function
  | "char" | "signed char" | "unsigned char" | "_Bool" | "bool" | "int8_t" | "uint8_t" -> Some (1,1)
  | "short" | "short int" | "unsigned short" | "unsigned short int" | "int16_t" | "uint16_t" -> Some (2,2)
  | "int" | "unsigned" | "unsigned int" | "float" | "wchar_t" | "int32_t" | "uint32_t" | "sgx_status_t" -> Some (4,4)
  | "long" | "long int" | "unsigned long" | "unsigned long int" | "long long" | "long long int"
  | "unsigned long long" | "unsigned long long int" | "double" | "size_t" | "ssize_t"
  | "intptr_t" | "uintptr_t" | "int64_t" | "uint64_t" -> Some (8,8)
  | _ -> None
let flags () = J.load (Sys.getenv "ENCBOUND_BRIDGE_FLAGS") |> J.arr |> List.map J.str
let layouts = Hashtbl.create 16
let scalar_types = Hashtbl.create 16
let copied_types = Hashtbl.create 16
let incomplete_buffers = Hashtbl.create 4
let generated_names = ref []
let pointer_results = Hashtbl.create 4
let user_types = Hashtbl.create 16
let void_buffers = Hashtbl.create 4
let scalar t = Hashtbl.mem scalar_types (Ast.get_tystr t)
let buffer_type t a d =
  if d.array_dims <> [] || a.pa_isary then Ast.get_tystr t
  else match t with
    | Ptr base -> Ast.get_tystr base
    | Foreign _ when a.pa_isptr -> "__typeof__(*((" ^ Ast.get_tystr t ^ ")0))"
    | _ -> fail "opaque pointer typedef requires isptr/isary"
let transport_type t d = Ast.get_tystr t ^ (if d.array_dims = [] then "" else " *")
let assertions = ref []
let assert_c s = assertions := s :: !assertions
let check_types ec preamble =
  let policy = J.get "records" (Lazy.force config) |> J.obj in
  let functions = List.filter_map (fun f -> if List.mem f.tf_fdecl.fname !sdk_names then None else Some f.tf_fdecl) ec.tfunc_decls @
    List.filter_map (fun f -> if List.mem f.uf_fdecl.fname !sdk_names then None else Some f.uf_fdecl) ec.ufunc_decls in
  (* Intel traverses EDL members carrying size/count attributes. Shallow C
   * pointer fields do not request that operation. Keep deep copy explicit. *)
  let deep_names = List.filter_map (function
    | StructDef s when List.exists (function
        | PTPtr (_,a),_ -> a.pa_size <> empty_ptr_size | _ -> false) s.smlist -> Some s.sname
    | _ -> None) ec.comp_defs in
  let rec deep_type = function Ptr t -> deep_type t
    | Struct n | Foreign n -> List.mem n deep_names | _ -> false in
  List.iter (fun fd -> List.iter (function
    | PTPtr (t,a),_ when a.pa_chkptr && deep_type t -> fail "EDL deep copy unsupported"
    | _ -> ()) fd.plist) functions;
  let scalars = ref [] and buffers = ref [] and results = ref [] and users = ref [] in
  let add_scalar t = if t <> Void && not (List.mem_assoc (Ast.get_tystr t) policy)
    then scalars := Ast.get_tystr t :: !scalars in
  List.iter (fun fd ->
    if fd.rtype <> Void && not (List.mem_assoc (Ast.get_tystr fd.rtype) policy)
    then results := Ast.get_tystr fd.rtype :: !results;
    List.iter (fun (p,d) -> match p with
      | PTVal t -> add_scalar t
      | PTPtr (t,a) when a.pa_chkptr ->
          let ty = buffer_type t a d in
          if ty <> "void" then buffers := (ty,a.pa_isary) :: !buffers
      | PTPtr (t,a) -> users := (transport_type t d,a.pa_isary) :: !users) fd.plist) functions;
  let scalars = List.sort_uniq String.compare !scalars in
  let buffers = List.sort_uniq compare !buffers in
  let results = List.sort_uniq String.compare !results in
  let users = List.sort_uniq compare !users in
  let probes = List.sort_uniq String.compare
      (scalars @ results @ List.map fst buffers @ List.map fst users) |>
    List.mapi (fun i ty -> ty, Printf.sprintf "_encbound_type_probe_%d" i) in
  if policy <> [] || probes <> [] then (
    let headers = List.map (fun (_,p) -> J.get "header" p |> J.str) policy |>
      List.filter (fun h -> not (List.mem h ec.include_list)) |> List.sort_uniq String.compare in
    let probe = Filename.concat (Sys.getenv "ENCBOUND_BRIDGE_WORK") "record-probe.c" in
    write probe ("#include <stddef.h>\n#include <stdint.h>\n#include <stdbool.h>\n#include <wchar.h>\n#include <sgx_edger8r.h>\n" ^
      String.concat "" (List.map (fun h -> "#include " ^ J.quote h ^ "\n") headers) ^
      preamble ^ "\n" ^
      String.concat "" (List.map (fun (n,_) -> if not (Util.is_c_identifier n) then fail "invalid record name";
        n ^ " encbound_record_probe_" ^ n ^ ";\n") policy) ^
      String.concat "" (List.map (fun (ty,n) -> "typedef " ^ ty ^ " " ^ n ^ ";\n") probes));
    let text = run_capture ([getenv "ENCBOUND_BRIDGE_LAYOUT_CC" "clang-21";
      "-Xclang"; "-ast-dump=json"; "-fsyntax-only"; "-MMD"; "-MF"; probe ^ ".d"; probe] @ flags () @
      (if profile="BASELINE" then [] else ["-DENCBOUND_PROTECTED"])) in
    let typedefs = Hashtbl.create 32 and records = Hashtbl.create 32 in
    let typedef_nodes = Hashtbl.create 32 and record_ids = Hashtbl.create 32 in
    let redeclarations = Hashtbl.create 16 in
    let children node = match J.get "inner" node with J.Array xs -> xs | _ -> [] in
    let rec collect node =
      let kind = J.get "kind" node and name = J.get "name" node in
      (* Function-local names do not participate in file-scope bridge types. *)
      if kind <> J.String "FunctionDecl" && kind <> J.String "BlockDecl" then (
        (match kind,name with
         | J.String "TypedefDecl", J.String n ->
             let typ = J.get "type" node in
             let ty = match J.get "desugaredQualType" typ with J.String _ as t -> t | _ -> J.get "qualType" typ in
             (match ty with J.String s -> Hashtbl.replace typedefs n s | _ -> ());
             Hashtbl.replace typedef_nodes n node
         | J.String "RecordDecl", _ ->
             let id = J.get "id" node |> J.str in
             Hashtbl.replace record_ids id node;
             (match J.get "previousDecl" node with J.String prev ->
               Hashtbl.replace redeclarations prev id | _ -> ());
             (match name with J.String n when J.get "completeDefinition" node = J.Bool true ->
               Hashtbl.replace records n node | _ -> ())
         | _ -> ());
        List.iter collect (children node)) in
    collect (J.parse text);
    let unqual ty =
      String.split_on_char ' ' (String.trim ty) |>
      List.filter (fun s -> s <> "const" && s <> "volatile" && s <> "restrict") |>
      String.concat " " in
    let rec resolve seen ty =
      let ty = unqual ty in
      if Hashtbl.mem typedefs ty then (
        if List.mem ty seen then fail ("recursive type alias: " ^ ty);
        resolve (ty::seen) (Hashtbl.find typedefs ty)) else ty in
    let arithmetic ty = match scalar_layout ty with Some _ -> true | None ->
      String.starts_with ~prefix:"enum " ty &&
      not (String.exists (fun c -> List.mem c ['*';'[';'(']) ty) in
    (* Follow Clang's type nodes, rather than printed anonymous names or local
     * tag spellings. typeof probes can also contain expression children. *)
    let rec core node =
      let kind = J.get "kind" node |> J.str in
      if List.mem kind ["TypedefDecl";"TypedefType";"ElaboratedType";
          "ParenType";"TypeOfExprType";"TypeOfType";"AttributedType";"QualType"] then
        match List.filter (fun n -> match J.get "kind" n with
          | J.String k -> String.ends_with ~suffix:"Type" k | _ -> false) (children node) |> List.rev with
        | n::_ -> core n | [] -> fail ("missing Clang type node: " ^ kind)
      else node in
    let probe_node ty = core (Hashtbl.find typedef_nodes (List.assoc ty probes)) in
    let probe_type ty = J.get "qualType" (J.get "type" (probe_node ty)) |> J.str |> unqual in
    let kind node = J.get "kind" node |> J.str in
    let is_array node = List.mem (kind node) ["ConstantArrayType";"IncompleteArrayType"] in
    let data_pointer node = kind node = "PointerType" &&
      match children node with
      | [pointee] -> not (List.mem (kind (core pointee)) ["FunctionProtoType";"FunctionNoProtoType"])
      | _ -> false in
    let rec latest_record id =
      if Hashtbl.mem redeclarations id then latest_record (Hashtbl.find redeclarations id) else id in
    let rec record_definition id =
      let node = Hashtbl.find record_ids id in
      if J.get "completeDefinition" node = J.Bool true then node
      else match J.get "previousDecl" node with
        | J.String prev -> record_definition prev | _ -> node in
    let record_node id = record_definition (latest_record id) in
    let rec complete node = match kind node with
      | "RecordType" -> J.get "completeDefinition"
          (record_node (J.get "id" (J.get "decl" node) |> J.str)) = J.Bool true
      | "IncompleteArrayType" -> false
      | "ConstantArrayType" -> (match children node with [n] -> complete (core n) | _ -> false)
      | "BuiltinType" -> probe_type_of_node node <> "void"
      | "FunctionProtoType" | "FunctionNoProtoType" -> fail "function buffer unsupported"
      | _ -> true
    and probe_type_of_node node = J.get "qualType" (J.get "type" node) |> J.str |> unqual in
    List.iter (fun ty ->
      if not (arithmetic (probe_type ty)) then fail ("unsupported value type: " ^ ty);
      Hashtbl.replace scalar_types ty ()) scalars;
    List.iter (fun ty ->
      if arithmetic (probe_type ty) then Hashtbl.replace scalar_types ty ()
      else if data_pointer (probe_node ty) then (
        Hashtbl.replace pointer_results ty ();
        assert_c (Printf.sprintf "_Static_assert(sizeof(%s)==8 && _Alignof(%s)==8,\"pointer result ABI\");" ty ty))
      else fail ("unsupported return ABI: " ^ ty)) results;
    List.iter (fun (ty,isary) ->
      let node = probe_node ty in
      if (isary && not (is_array node)) ||
         not (data_pointer node || (isary && is_array node)) then fail "unsupported user_check shape";
      Hashtbl.replace user_types ty ()) users;
    List.iter (fun (ty,isary) ->
      let node = probe_node ty in
      if isary && not (is_array node) then fail "isary requires an array typedef";
      if probe_type ty = "void" then Hashtbl.replace void_buffers ty ()
      else if complete node then
        assert_c (Printf.sprintf "_Static_assert(_Alignof(%s)<=16,\"copied buffer alignment\");" ty)
      else Hashtbl.replace incomplete_buffers ty ();
      Hashtbl.replace copied_types ty ()) buffers;
    let visiting = ref [] in
    let round n a = (n+a-1)/a*a in
    let rec member ty =
      let ty = String.trim ty in
      (* Resolve typedefs before recognizing scalar spellings: a header-defined
       * alias such as ssize_t can itself hide a pointer. Only file-scope declarations
       * participate; unrelated function-local declarations cannot replace them. *)
      if Hashtbl.mem typedefs ty then (
        let target = resolve [] ty in
        if target = ty then fail ("unresolved value-record alias: " ^ ty);
        member target)
      else
      match scalar_layout ty with Some x -> x | None ->
      if String.contains ty '*' || String.contains ty '(' then fail ("pointer/unsupported record member: " ^ ty);
      if String.ends_with ~suffix:"]" ty then (
        let k = try String.rindex ty '[' with _ -> fail "bad record array" in
        let count = try int_of_string (String.sub ty (k+1) (String.length ty-k-2)) with _ -> fail "nonconstant record array" in
        if count <= 0 then fail "nonpositive record array";
        let s,a = member (String.sub ty 0 k) in
        if count > max_int / s then fail "record array overflow"; s*count,a)
      else if String.starts_with ~prefix:"struct " ty then record ty (String.sub ty 7 (String.length ty-7))
      else fail ("unknown record member: " ^ ty)
    and record ctype tag =
      if List.mem tag !visiting then fail "recursive record";
      let node = try Hashtbl.find records tag with Not_found -> fail ("incomplete record: " ^ tag) in
      if J.get "tagUsed" node <> J.String "struct" then fail "only pointer-free structs are supported";
      visiting := tag :: !visiting;
      let offset = ref 0 and alignment = ref 1 and fields = ref 0 in
      let children = match J.get "inner" node with J.Array xs -> xs | _ -> [] in
      List.iter (fun field -> match J.get "kind" field with
        | J.String "FieldDecl" ->
          if J.get "isBitfield" field = J.Bool true then fail "record bitfields unsupported";
          let name = J.get "name" field |> J.str in
          let ty = J.get "qualType" (J.get "type" field) |> J.str in
          let s,a = member ty in offset := round !offset a;
          assert_c (Printf.sprintf "_Static_assert(offsetof(%s,%s)==%d,\"record offset\");" ctype name !offset);
          if s > max_int - !offset then fail "record size overflow";
          offset := !offset+s; alignment := max !alignment a; incr fields
        | J.String "PackedAttr" | J.String "AlignedAttr" -> fail "custom record alignment unsupported"
        | _ -> ()) children;
      if !fields = 0 then fail "empty record unsupported";
      visiting := List.tl !visiting;
      let size = round !offset !alignment in
      assert_c (Printf.sprintf "_Static_assert(sizeof(%s)==%d && _Alignof(%s)==%d,\"record layout\");" ctype size ctype !alignment);
      Hashtbl.replace layouts ctype (size,!alignment); size,!alignment in
    List.iter (fun (n,_) ->
      let ty = try Hashtbl.find typedefs n with _ -> fail ("record is not a struct typedef: " ^ n) in
      if not (String.starts_with ~prefix:"struct " ty) then fail ("record is not a struct: " ^ n);
      let s,a = member ty in Hashtbl.replace layouts n (s,a)) policy)
let value_record = function
  | PTVal t -> Hashtbl.mem layouts (Ast.get_tystr t)
  | _ -> false
let record_function fd = List.exists (fun (p,_) -> value_record p) fd.plist
let application_entry fd = "__encbound_edl_app_" ^ fd.fname
let trusted_proxy fd = "__encbound_edl_proxy_" ^ fd.fname
let validate_function fd =
  let rec check_scalar_type = function
    | Ptr t -> check_scalar_type t
    | t when scalar t ->
      let ty = get_tystr t in
      (match scalar_layout ty with Some (s,a) ->
        assert_c (Printf.sprintf "_Static_assert(sizeof(%s)==%d && _Alignof(%s)==%d,\"scalar ABI\");" ty s ty a)
       | None -> assert_c (Printf.sprintf "_Static_assert(sizeof(%s)<=8 && _Alignof(%s)<=8,\"scalar ABI\");" ty ty));
      (match t with
       | Int8 | Int16 | Int32 | Int64 -> assert_c (Printf.sprintf "_Static_assert((%s)-1 < 0,\"signed scalar\");" ty)
       | UInt8 | UInt16 | UInt32 | UInt64 | SizeT -> assert_c (Printf.sprintf "_Static_assert((%s)-1 > 0,\"unsigned scalar\");" ty)
       | Foreign "bool" | Foreign "_Bool" -> assert_c (Printf.sprintf "_Static_assert(__builtin_types_compatible_p(%s,_Bool),\"bool ABI\");" ty)
       | _ -> ())
    | _ -> () in
  check_scalar_type fd.rtype;
  List.iter (fun (p,_) -> check_scalar_type (get_param_atype p)) fd.plist;
  let reserved n = List.exists (fun p -> String.starts_with ~prefix:p n) ["encbound_";"__encbound_"] in
  if reserved fd.fname || List.mem fd.fname !sdk_names || List.mem fd.fname !generated_names ||
     List.mem fd.fname ["sgx_ecall";"sgx_ecall_switchless";"sgx_ocall";"sgx_ocall_switchless";
       "sgx_ocalloc";"sgx_ocfree";"sgx_is_outside_enclave";"sgx_is_within_enclave";"sgx_lfence"] then fail ("reserved interface name: " ^ fd.fname);
  if not (fd.rtype = Void || scalar fd.rtype || Hashtbl.mem pointer_results (get_tystr fd.rtype))
  then fail "unsupported return ABI";
  let seen = ref [] in
  List.iter (fun (pt,d) ->
    if List.mem d.identifier !seen then fail "duplicate parameter"; seen := d.identifier :: !seen;
    if String.starts_with ~prefix:"_encbound_" d.identifier then fail "reserved generated parameter name";
    ignore (List.fold_left (fun n dim ->
      if dim <= 0 || n > max_int / dim then fail "invalid/overflowing array dimensions";
      n*dim) 1 d.array_dims);
    match pt with
    | PTVal t ->
      if scalar t then ()
      else if Hashtbl.mem layouts (get_tystr t) then ()
      else fail ("unsupported value type: " ^ get_tystr t)
    | PTPtr (t,a) ->
      if not a.pa_chkptr then (
        if a.pa_direction <> PtrNoDirection || a.pa_isstr || a.pa_iswstr ||
           a.pa_size <> empty_ptr_size || not (Hashtbl.mem user_types (transport_type t d)) then fail "unsupported user_check shape")
      else (
        let ty = buffer_type t a d in
        if ty <> "void" && not (Hashtbl.mem copied_types ty) then fail ("unknown pointer element: " ^ ty);
        if a.pa_direction = PtrNoDirection then fail "copied pointer requires direction";
        if a.pa_rdonly && (a.pa_direction = PtrOut || a.pa_direction = PtrInOut) then fail "const output pointer";
        if a.pa_isstr || a.pa_iswstr then (
          if not (List.mem a.pa_direction [PtrIn;PtrInOut]) || a.pa_size <> empty_ptr_size ||
             (if a.pa_iswstr then t <> Ptr WChar else match t with Ptr (Char _) -> false | _ -> true)
          then fail "unsupported string shape")
        else (
          if (ty = "void" || Hashtbl.mem void_buffers ty || Hashtbl.mem incomplete_buffers ty) &&
             a.pa_size.ps_size = None then fail "void/incomplete buffer needs a byte size";
          List.iter (function
           | None -> ()
           | Some (ANumber n) -> if n < 0 then fail "negative extent"
           | Some (AString n) ->
             let length = try List.find (fun (_,d) -> d.identifier=n) fd.plist with _ -> fail "extent is not a parameter" in
             match fst length with
             | PTVal t when scalar t ->
                 let ty = get_tystr t in
                 assert_c (Printf.sprintf "_Static_assert(__builtin_classify_type((%s)0)==1,\"integer extent parameter\");" ty)
             | _ -> fail "extent requires an integer value parameter")
            [a.pa_size.ps_size;a.pa_size.ps_count]))) fd.plist
let validate root ec preamble = if enabled then (
  if not (List.mem profile ["BASELINE";"RADIX_ONLY";"MAC27"]) then fail "missing protection profile";
  let cfg = Lazy.force config in
  if List.sort String.compare (List.map fst (J.obj cfg)) <> ["records";"sdk_only_imports"] then fail "unknown interface metadata";
  let declared = J.get "sdk_only_imports" cfg |> J.obj |> List.map fst |> List.sort_uniq String.compare in
  if declared <> List.sort_uniq String.compare !imported then fail "unused SDK import metadata";
  (* Preserve declaration origin even for selective imports. An app declaration
   * cannot acquire a raw SDK proxy merely by reusing an unselected SDK name. *)
  observe_application root;
  List.iter (fun name -> if List.mem name !sdk_names
    then fail ("application ECALL shadows SDK import: " ^ name)) !application_tnames;
  List.iter (fun name -> if List.mem name !sdk_names
    then fail ("application OCALL shadows SDK import: " ^ name)) !application_unames;
  generated_names := List.map (fun tf -> "sgx_" ^ tf.tf_fdecl.fname) ec.tfunc_decls;
  check_types ec preamble;
  List.iter (fun tf -> if tf.tf_is_priv || tf.tf_is_switchless then fail "private/switchless ECALL unsupported";
    if not (List.mem tf.tf_fdecl.fname !sdk_names) then validate_function tf.tf_fdecl) ec.tfunc_decls;
  let app_ecalls = List.filter (fun tf -> not (List.mem tf.tf_fdecl.fname !sdk_names)) ec.tfunc_decls in
  let app_ocalls = List.filter (fun uf -> not (List.mem uf.uf_fdecl.fname !sdk_names)) ec.ufunc_decls in
  List.iter (fun uf -> if uf.uf_is_switchless || uf.uf_allow_list <> [] ||
    not (List.mem uf.uf_fattr.fa_convention [CC_NONE;CC_CDECL]) || uf.uf_fattr.fa_dllimport then fail "unsupported OCALL mode";
    validate_function uf.uf_fdecl) app_ocalls;
  ecalls := List.map (fun f -> f.tf_fdecl.fname) app_ecalls;
  sdk_ecalls := List.filter_map (fun f -> if List.mem f.tf_fdecl.fname !sdk_names
    then Some f.tf_fdecl.fname else None) ec.tfunc_decls;
  ocalls := List.map (fun f -> f.uf_fdecl.fname) app_ocalls;
  (* BASELINE also consumes the application-libc environment. Keep this list
   * independent of the protected-only marshaling selections in CodeGen. *)
  errno_ocalls := List.filter_map (fun f ->
    if f.uf_propagate_errno then Some f.uf_fdecl.fname else None) app_ocalls)
let emit ec prototypes = if enabled then (
  let dir = Sys.getenv "ENCBOUND_BRIDGE_WORK" in
  let strings xs = J.Array (List.map (fun s -> J.String s) xs) in
  let user_checks functions = List.filter_map (fun fd ->
    let ps = List.filter_map (fun (p,d) -> match p with PTPtr (_,a) when not a.pa_chkptr -> Some d.identifier | _ -> None) fd.plist in
    if ps=[] then None else Some (fd.fname,strings ps)) functions in
  let adapted_ecalls = if profile="BASELINE" then [] else
    List.filter (fun f -> List.mem f.tf_fdecl.fname !ecalls && record_function f.tf_fdecl) ec.tfunc_decls in
  let adapted_ocalls = if profile="BASELINE" then [] else
    List.filter (fun f -> List.mem f.uf_fdecl.fname !ocalls && record_function f.uf_fdecl) ec.ufunc_decls in
  let app_definitions = List.map (fun f -> application_entry f.tf_fdecl) adapted_ecalls @
    List.map (fun f -> f.uf_fdecl.fname) adapted_ocalls in
  let trusted_ocalls = List.map (fun f ->
    if List.exists (fun a -> a.uf_fdecl.fname=f.uf_fdecl.fname) adapted_ocalls
    then trusted_proxy f.uf_fdecl else f.uf_fdecl.fname)
    (List.filter (fun f -> List.mem f.uf_fdecl.fname !ocalls) ec.ufunc_decls) in
  let eh_entries = if not cxx_eh then [] else List.map (fun f ->
    if profile<>"BASELINE" && record_function f.tf_fdecl then application_entry f.tf_fdecl
    else f.tf_fdecl.fname) (List.filter (fun f -> List.mem f.tf_fdecl.fname !ecalls) ec.tfunc_decls) in
  let manifest = J.Object ["ecalls",strings (List.map (fun f -> f.tf_fdecl.fname) ec.tfunc_decls);
    "application_ecalls",strings !ecalls;"sdk_ecalls",strings !sdk_ecalls;
    "sdk_ecall_imports",strings (List.sort_uniq String.compare !sdk_ecall_origins);
    "ocalls",strings !ocalls;
    "propagate_errno_ocalls",strings !errno_ocalls;
    "required_application_symbols",strings (if !errno_ocalls=[] then [] else errno_symbols);
    "eh_entries",strings eh_entries;
    "application_definitions",strings app_definitions;"trusted_ocalls",strings trusted_ocalls;
    "record_ecalls",strings (List.map (fun f -> f.tf_fdecl.fname) adapted_ecalls);
    "record_ocalls",strings (List.map (fun f -> f.uf_fdecl.fname) adapted_ocalls);
    "sdk_only",strings !sdk_names;
    "imports",J.Array (List.rev !import_origins);
    "user_check_ecalls",J.Object (user_checks (List.map (fun f -> f.tf_fdecl) ec.tfunc_decls));
    "user_check_ocalls",J.Object (user_checks (List.filter_map (fun f ->
      if List.mem f.uf_fdecl.fname !ocalls then Some f.uf_fdecl else None) ec.ufunc_decls));
    "dependencies",strings (List.sort_uniq String.compare !dependencies)] in
  write (Filename.concat dir "edger8r-admission.json") (J.show manifest ^ "\n");
  write (Filename.concat dir "admitted-ocalls.txt") (String.concat "\n" trusted_ocalls ^ "\n");
  write (Filename.concat dir "admitted-app.txt") (String.concat "\n" app_definitions ^ "\n");
  write (Filename.concat dir "eh-entries.txt") (String.concat "\n" eh_entries ^ "\n");
  write (Filename.concat dir "bridge-abi.c") ("#include \"" ^ ec.file_shortnm ^ "_t.h\"\n#include <stddef.h>\n" ^
    String.concat "\n" (List.rev !assertions) ^ "\n" ^ prototypes ^ "\n"))
