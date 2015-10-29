//var path = require('path');
var fs = require('fs');

var pkg = JSON.parse(fs.readFileSync('./package.json', 'utf-8'));
var root = __dirname;

config = {
  doc: root + '/doc/',
  project: root + '/src/tsconfig.json',
//  sources: 'src/**/*.ts',
  karma: root + '/karma.conf.js',
  tests: root + '/test/**/*.ts',
  tslibs: root + '/dist/*.d.ts',
  output: root + '/dist/',
  packageName: pkg.name,
  packageVersion: pkg.version
};

require('cgfx-build-tools');
