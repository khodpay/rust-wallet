// @dart=3.6
// ignore_for_file: directives_ordering
// build_runner >=2.4.16
// ignore_for_file: no_leading_underscores_for_library_prefixes
import 'package:build_runner_core/build_runner_core.dart' as _i1;
import 'package:source_gen/builder.dart' as _i2;
import 'package:freezed/builder.dart' as _i3;
import 'dart:isolate' as _i4;
import 'package:build_runner/src/build_script_generate/build_process_state.dart'
    as _i5;
import 'package:build_runner/build_runner.dart' as _i6;
import 'dart:io' as _i7;

final _builders = <_i1.BuilderApplication>[
  _i1.apply(
    r'source_gen:combining_builder',
    [_i2.combiningBuilder],
    _i1.toNoneByDefault(),
    hideOutput: false,
    appliesBuilders: const [r'source_gen:part_cleanup'],
  ),
  _i1.apply(
    r'freezed:freezed',
    [_i3.freezed],
    _i1.toDependentsOf(r'freezed'),
    hideOutput: false,
  ),
  _i1.applyPostProcess(
    r'source_gen:part_cleanup',
    _i2.partCleanup,
  ),
];
void main(
  List<String> args, [
  _i4.SendPort? sendPort,
]) async {
  await _i5.buildProcessState.receive(sendPort);
  _i5.buildProcessState.isolateExitCode = await _i6.run(
    args,
    _builders,
  );
  _i7.exitCode = _i5.buildProcessState.isolateExitCode!;
  await _i5.buildProcessState.send(sendPort);
}
