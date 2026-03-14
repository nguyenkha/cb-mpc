/** Type declaration for the Emscripten-generated glue code. */
declare module "../cbmpc.js" {
  import type { CbMpcWasmModule } from "./types";
  const createCbMpc: (opts?: object) => Promise<CbMpcWasmModule>;
  export default createCbMpc;
  export { createCbMpc };
}
