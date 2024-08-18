# Copyright 2024 The TensorFlow Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""The central place to define flags."""

from absl import flags


def define_flags():
  """Defines flags.

  All flags are defined as optional, but in practice most models use some of
  these flags and so mark_flags_as_required() should be called after calling
  this function. Typically, 'experiment', 'mode', and 'model_dir' are required.
  For example:

  ```
  from absl import flags
  from official.common import flags as tfm_flags  # pylint: disable=line-too-long
  ...
  tfm_flags.define_flags()
  flags.mark_flags_as_required(['experiment', 'mode', 'model_dir'])
  ```

  The reason all flags are optional is because unit tests often do not set or
  use any of the flags.
  """
  flags.DEFINE_string(
      'experiment', default=None, help=
      'The experiment type registered, specifying an ExperimentConfig.')

  flags.DEFINE_enum(
      'mode',
      default=None,
      enum_values=[
          'train', 'eval', 'train_and_eval', 'continuous_eval',
          'continuous_train_and_eval', 'train_and_validate',
          'train_and_post_eval'
      ],
      help='Mode to run: `train`, `eval`, `train_and_eval`, '
      '`continuous_eval`, `continuous_train_and_eval` and '
      '`train_and_validate` (which is not implemented in '
      'the open source version).')

  flags.DEFINE_string(
      'model_dir',
      default=None,
      help='The directory where the model and training/evaluation summaries'
      'are stored.')

  flags.DEFINE_multi_string(
      'config_file',
      default=None,
      help='YAML/JSON files which specifies overrides. The override order '
      'follows the order of args. Note that each file '
      'can be used as an override template to override the default parameters '
      'specified in Python. If the same parameter is specified in both '
      '`--config_file` and `--params_override`, `config_file` will be used '
      'first, followed by params_override.')

  flags.DEFINE_string(
      'params_override',
      default=None,
      help='a YAML/JSON string or a YAML file which specifies additional '
      'overrides over the default parameters and those specified in '
      '`--config_file`. Note that this is supposed to be used only to override '
      'the model parameters, but not the parameters like TPU specific flags. '
      'One canonical use case of `--config_file` and `--params_override` is '
      'users first define a template config file using `--config_file`, then '
      'use `--params_override` to adjust the minimal set of tuning parameters, '
      'for example setting up different `train_batch_size`. The final override '
      'order of parameters: default_model_params --> params from config_file '
      '--> params in params_override. See also the help message of '
      '`--config_file`.')

  # The libraries rely on gin often make mistakes that include flags inside
  # the library files which causes conflicts.
  try:
    flags.DEFINE_multi_string(
        'gin_file', default=None, help='List of paths to the config files.')
  except flags.DuplicateFlagError:
    pass

  try:
    flags.DEFINE_multi_string(
        'gin_params',
        default=None,
        help='Newline separated list of Gin parameter bindings.')
  except flags.DuplicateFlagError:
    pass

  flags.DEFINE_string(
      'tpu',
      default=None,
      help='The Cloud TPU to use for training. This should be either the name '
      'used when creating the Cloud TPU, or a grpc://ip.address.of.tpu:8470 '
      'url.')

  flags.DEFINE_string(
      'tf_data_service', default=None, help='The tf.data service address')

  flags.DEFINE_string(
      'tpu_platform', default=None, help='TPU platform type.')

  flags.DEFINE_string(
      'tfhub_handle',
      None,
      'TFHub handle for publishing the model to TFHub. The model '
      'is published to TFHub if this flag is set. Please use a '
      'TFHubPusher (go/tflex/standard_components/pusher) component if '
      'running in TFleX.',
  )


# Copyright 2024 The TensorFlow Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Common flags for SuperGLUE finetuning binary."""
from typing import Callable

from absl import flags
from absl import logging


def define_flags():
  """Defines flags."""

  # ===========================================================================
  # SuperGlue binary flags.
  # ===========================================================================
  flags.DEFINE_enum(
      'mode', 'train_eval_and_predict',
      ['train_eval_and_predict', 'train_eval', 'predict'],
      'The mode to run the binary. If `train_eval_and_predict` '
      'it will (1) train on the training data and (2) evaluate on '
      'the validation data and (3) finally generate predictions '
      'on the prediction data; if `train_eval`, it will only '
      'run training and evaluation; if `predict`, it will only '
      'run prediction using the model in `model_dir`.')

  flags.DEFINE_enum('task_name', None, [
      'AX-b',
      'CB',
      'COPA',
      'MULTIRC',
      'RTE',
      'WiC',
      'WSC',
      'BoolQ',
      'ReCoRD',
      'AX-g',
  ], 'The type of SuperGLUE task.')

  flags.DEFINE_string('train_input_path', None,
                      'The file path to the training data.')

  flags.DEFINE_string('validation_input_path', None,
                      'The file path to the evaluation data.')

  flags.DEFINE_string('test_input_path', None,
                      'The file path to the test input data.')

  flags.DEFINE_string('test_output_path', None,
                      'The file path to the test output data.')

  flags.DEFINE_string(
      'model_dir', '', 'The model directory containing '
      'subdirectories for each task. Only needed for "predict" '
      'mode. For all other modes, if not provided, a unique '
      'directory will be created automatically for each run.')

  flags.DEFINE_string(
      'input_meta_data_path', None, 'Path to file that contains '
      'metadata about input file. It is output by the `create_finetuning_data` '
      'binary. Required for all modes except "predict".')

  flags.DEFINE_string('init_checkpoint', '',
                      'Initial checkpoint from a pre-trained BERT model.')

  flags.DEFINE_string(
      'model_config_file', '', 'The config file specifying the architecture '
      'of the pre-trained model. The file can be either a bert_config.json '
      'file or `encoders.EncoderConfig` in yaml file.')

  flags.DEFINE_string(
      'hub_module_url', '', 'TF-Hub path/url to a pretrained model. If '
      'specified, `init_checkpoint` and `model_config_file` flag should not be '
      'used.')

  flags.DEFINE_multi_string('gin_file', None,
                            'List of paths to the gin config files.')

  flags.DEFINE_multi_string(
      'gin_params', None, 'Newline separated list of gin parameter bindings.')

  flags.DEFINE_multi_string(
      'config_file', None, 'This is the advanced usage to specify the '
      '`ExperimentConfig` directly. When specified, '
      'we will ignore FLAGS related to `ExperimentConfig` such as '
      '`train_input_path`, `validation_input_path` and following hparams.')

  # ===========================================================================
  # Tuning hparams.
  # ===========================================================================
  flags.DEFINE_integer('global_batch_size', 32,
                       'Global batch size for train/eval/predict.')

  flags.DEFINE_float('learning_rate', 3e-5, 'Initial learning rate.')

  flags.DEFINE_integer('num_epoch', 3, 'Number of training epochs.')

  flags.DEFINE_float('warmup_ratio', 0.1,
                     'Proportion of learning rate warmup steps.')

  flags.DEFINE_integer('num_eval_per_epoch', 2,
                       'Number of evaluations to run per epoch.')


def validate_flags(flags_obj: flags.FlagValues, file_exists_fn: Callable[[str],
                                                                         bool]):
  """Raises ValueError if any flags are misconfigured.

  Args:
    flags_obj: A `flags.FlagValues` object, usually from `flags.FLAG`.
    file_exists_fn: A callable to decide if a file path exists or not.
  """

  def _check_path_exists(flag_path, flag_name):
    if not file_exists_fn(flag_path):
      raise ValueError('Flag `%s` at %s does not exist.' %
                       (flag_name, flag_path))

  def _validate_path(flag_path, flag_name):
    if not flag_path:
      raise ValueError('Flag `%s` must be provided in mode %s.' %
                       (flag_name, flags_obj.mode))
    _check_path_exists(flag_path, flag_name)

  if 'train' in flags_obj.mode:
    _validate_path(flags_obj.train_input_path, 'train_input_path')
    _validate_path(flags_obj.input_meta_data_path, 'input_meta_data_path')

    if flags_obj.gin_file:
      for gin_file in flags_obj.gin_file:
        _check_path_exists(gin_file, 'gin_file')
    if flags_obj.config_file:
      for config_file in flags_obj.config_file:
        _check_path_exists(config_file, 'config_file')

  if 'eval' in flags_obj.mode:
    _validate_path(flags_obj.validation_input_path, 'validation_input_path')

  if flags_obj.mode == 'predict':
    # model_dir is only needed strictly in 'predict' mode.
    _validate_path(flags_obj.model_dir, 'model_dir')

  if 'predict' in flags_obj.mode:
    _validate_path(flags_obj.test_input_path, 'test_input_path')

  if not flags_obj.config_file and flags_obj.mode != 'predict':
    if flags_obj.hub_module_url:
      if flags_obj.init_checkpoint or flags_obj.model_config_file:
        raise ValueError(
            'When `hub_module_url` is specified, `init_checkpoint` and '
            '`model_config_file` should be empty.')
      logging.info('Using the pretrained tf.hub from %s',
                   flags_obj.hub_module_url)
    else:
      if not (flags_obj.init_checkpoint and flags_obj.model_config_file):
        raise ValueError('Both `init_checkpoint` and `model_config_file` '
                         'should be specified if `config_file` is not '
                         'specified.')
      _validate_path(flags_obj.model_config_file, 'model_config_file')
      logging.info(
          'Using the pretrained checkpoint from %s and model_config_file from '
          '%s.', flags_obj.init_checkpoint, flags_obj.model_config_file)
# Copyright 2024 The TensorFlow Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Common flags for GLUE finetuning binary."""
from typing import Callable

from absl import flags
from absl import logging


def define_flags():
  """Defines flags."""

  # ===========================================================================
  # Glue binary flags.
  # ===========================================================================
  flags.DEFINE_enum('task_name', None, [
      'AX', 'COLA', 'MNLI', 'MRPC', 'QNLI', 'QQP', 'RTE', 'SST-2', 'STS-B',
      'WNLI'
  ], 'The type of GLUE task.')

  flags.DEFINE_string('train_input_path', None,
                      'The file path to the training data.')

  flags.DEFINE_string('validation_input_path', None,
                      'The file path to the evaluation data.')

  flags.DEFINE_string('test_input_path', None,
                      'The file path to the test input data.')

  flags.DEFINE_string('test_output_path', None,
                      'The file path to the test output data.')

  flags.DEFINE_string('model_dir', '', 'The model directory containing '
                      'subdirectories for each task. Only needed for "predict" '
                      'mode. For all other modes, if not provided, a unique '
                      'directory will be created automatically for each run.')

  flags.DEFINE_string(
      'input_meta_data_path', None, 'Path to file that contains '
      'metadata about input file. It is output by the `create_finetuning_data` '
      'binary. Required for all modes except "predict".')

  flags.DEFINE_string('init_checkpoint', '',
                      'Initial checkpoint from a pre-trained BERT model.')

  flags.DEFINE_string(
      'model_config_file', '', 'The config file specifying the architecture '
      'of the pre-trained model. The file can be either a bert_config.json '
      'file or `encoders.EncoderConfig` in yaml file.')

  flags.DEFINE_string(
      'hub_module_url', '', 'TF-Hub path/url to a pretrained model. If '
      'specified, `init_checkpoint` and `model_config_file` flag should not be '
      'used.')

  flags.DEFINE_multi_string('gin_file', None,
                            'List of paths to the gin config files.')

  flags.DEFINE_multi_string('gin_params', None,
                            'Newline separated list of gin parameter bindings.')

  flags.DEFINE_multi_string(
      'config_file', None, 'This is the advanced usage to specify the '
      '`ExperimentConfig` directly. When specified, '
      'we will ignore FLAGS related to `ExperimentConfig` such as '
      '`train_input_path`, `validation_input_path` and following hparams.')

  # ===========================================================================
  # Tuning hparams.
  # ===========================================================================
  flags.DEFINE_integer('global_batch_size', 32,
                       'Global batch size for train/eval/predict.')

  flags.DEFINE_float('learning_rate', 3e-5, 'Initial learning rate.')

  flags.DEFINE_integer('num_epoch', 3, 'Number of training epochs.')

  flags.DEFINE_float('warmup_ratio', 0.1,
                     'Proportion of learning rate warmup steps.')

  flags.DEFINE_integer('num_eval_per_epoch', 2,
                       'Number of evaluations to run per epoch.')


def validate_flags(flags_obj: flags.FlagValues,
                   file_exists_fn: Callable[[str], bool]):
  """Raises ValueError if any flags are misconfigured.

  Args:
    flags_obj: A `flags.FlagValues` object, usually from `flags.FLAG`.
    file_exists_fn: A callable to decide if a file path exists or not.
  """

  def _check_path_exists(flag_path, flag_name):
    if not file_exists_fn(flag_path):
      raise ValueError('Flag `%s` at %s does not exist.' %
                       (flag_name, flag_path))

  def _validate_path(flag_path, flag_name):
    if not flag_path:
      raise ValueError('Flag `%s` must be provided in mode %s.' %
                       (flag_name, flags_obj.mode))
    _check_path_exists(flag_path, flag_name)

  if 'train' in flags_obj.mode:
    _validate_path(flags_obj.train_input_path, 'train_input_path')
    _validate_path(flags_obj.input_meta_data_path, 'input_meta_data_path')

    if flags_obj.gin_file:
      for gin_file in flags_obj.gin_file:
        _check_path_exists(gin_file, 'gin_file')
    if flags_obj.config_file:
      for config_file in flags_obj.config_file:
        _check_path_exists(config_file, 'config_file')

  if 'eval' in flags_obj.mode:
    _validate_path(flags_obj.validation_input_path, 'validation_input_path')

  if flags_obj.mode == 'predict':
    # model_dir is only needed strictly in 'predict' mode.
    _validate_path(flags_obj.model_dir, 'model_dir')

  if 'predict' in flags_obj.mode:
    _validate_path(flags_obj.test_input_path, 'test_input_path')

  if not flags_obj.config_file and flags_obj.mode != 'predict':
    if flags_obj.hub_module_url:
      if flags_obj.init_checkpoint or flags_obj.model_config_file:
        raise ValueError(
            'When `hub_module_url` is specified, `init_checkpoint` and '
            '`model_config_file` should be empty.')
      logging.info(
          'Using the pretrained tf.hub from %s', flags_obj.hub_module_url)
    else:
      if not (flags_obj.init_checkpoint and flags_obj.model_config_file):
        raise ValueError('Both `init_checkpoint` and `model_config_file` '
                         'should be specified if `config_file` is not '
                         'specified.')
      _validate_path(flags_obj.model_config_file, 'model_config_file')
      logging.info(
          'Using the pretrained checkpoint from %s and model_config_file from '
          '%s.', flags_obj.init_checkpoint, flags_obj.model_config_file)
