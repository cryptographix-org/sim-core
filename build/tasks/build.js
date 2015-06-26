var gulp = require('gulp');
var runSequence = require('run-sequence');
var ts = require('gulp-typescript');
var paths = require('../paths');
var compilerOptions = require('../typescript-options');
var assign = Object.assign || require('object.assign');

compilerOptions = assign({}, compilerOptions, {typescript: require('typescript')});

gulp.task('build-es6', function () {
  return gulp.src(paths.source)
    .pipe(ts(assign({}, compilerOptions, {target:'es6'})))
    .js.pipe(gulp.dest(paths.output + 'es6'));
});

gulp.task('build-commonjs', function () {
  return gulp.src(paths.source)
    .pipe(ts(assign({}, compilerOptions, { target:'es5', module: 'commonjs' })))
    .pipe(gulp.dest(paths.output + 'commonjs'));
});

gulp.task('build-amd', function () {
  return gulp.src(paths.source)
    .pipe(ts(assign({}, compilerOptions, { target:'es5', module: 'amd' })))
    .pipe(gulp.dest(paths.output + 'amd'));
});

gulp.task('build-system', function () {
  return gulp.src(paths.source)
    .pipe(ts(assign({}, compilerOptions, { target:'es5', module: 'system' })))
    .pipe(gulp.dest(paths.output + 'system'));
});

gulp.task('build', function(callback) {
  return runSequence(
    'clean',
    ['build-es6', 'build-commonjs', 'build-amd', 'build-system'],
    callback
  );
});
