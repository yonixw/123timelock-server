import * as sjcl from "./custom_sjcl_1.0.8";

export function hash256(text: string): string {
  let hash = new sjcl.hash.sha256();
  hash.update(text);
  let uint32_arr = hash.finalize() as Array<number>;
  return sjcl.codec.hex.fromBits(uint32_arr);
}

export function gen(count: number) {
  return new Array(count)
    .fill(0)
    .map((e, i) => (i % 10).toString(10))
    .join("");
}

export function hash256Step(text: string, state?: string): string {
  let hash = new sjcl.hash.sha256();
  if (state) {
    hash.import(state);
  }
  hash.update(text);
  return hash.export();
}

export function hash256FinalStep(text: string, state?: string): string {
  let hash = new sjcl.hash.sha256();
  if (state) {
    hash.import(state);
  }
  hash.update(text);
  let uint32_arr = hash.finalize() as Array<number>;
  return sjcl.codec.hex.fromBits(uint32_arr);
}
