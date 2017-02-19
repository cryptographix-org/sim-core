import { Network } from './network';
import { NodeRuntimeContext } from './runtime-contexts';

export enum RunState {
  UNLOADED,     // Not yet loaded
  LOADING,      // Waiting for async load to complete
  LOADED,       // Component loaded, not yet executable
  READY,        // Ready for Execution
  RUNNING,      // Network active, and running
  PAUSED        // Network temporarily paused
}

export { Network };
export { NodeRuntimeContext };
