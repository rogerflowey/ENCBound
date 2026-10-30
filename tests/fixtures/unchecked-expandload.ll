; Review reproducer: this memory intrinsic must be rejected by the admitted
; subset. On the reviewed pass it survives unchanged and receives an audit
; marker, while the compiler driver reports zero checks. See the project review.
target triple = "x86_64-pc-linux-gnu"

declare <4 x i32> @llvm.masked.expandload.v4i32(ptr, <4 x i1>, <4 x i32>)

define <4 x i32> @unchecked_expandload(ptr %p, <4 x i1> %mask) {
entry:
  %value = call <4 x i32> @llvm.masked.expandload.v4i32(ptr %p, <4 x i1> %mask, <4 x i32> zeroinitializer)
  ret <4 x i32> %value
}
