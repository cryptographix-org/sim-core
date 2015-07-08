var path = require('path');
var fs = require('fs');

var appRoot = 'src/';
var pkg = JSON.parse(fs.readFileSync('./package.json', 'utf-8'));

paths = {
  root: appRoot,
  project: './src/tsconfig.json',
  source: appRoot + '**/*.ts',
  output: 'dist/',
  packageName: pkg.name
};

require('cgfx-build-tools');
