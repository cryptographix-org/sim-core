declare System: {};

class ModuleRegistryEntry {

}

export class ModuleLoader {

  moduleRegistry: Map<string, ModuleRegistryEntry>;

  constructor() {
    this.moduleRegistry = new Map<string, ModuleRegistryEntry>();
  }

  getOrCreateModuleRegistryEntry(address: string): ModuleRegistryEntry {
    return this.moduleRegistry[address] || (this.moduleRegistry[address] = new ModuleRegistryEntry(address));
  }

  loadModule( id: string ): Promise<any> {
    let newId = System.normalizeSync(id);
    let existing = this.moduleRegistry[newId];

    if (existing) {
      return Promise.resolve(existing);
    }

    return System.import(newId).then(m => {
      this.moduleRegistry[newId] = m;
      return m; //ensureOriginOnExports(m, newId);
    });
  }

}
