from __future__ import annotations

import logging
from ._builder import ProjectBuilder
from ._exceptions import (
    BuildBackendException,
    BuildException,
    BuildSystemTableValidationError,
    FailedProcessError,
    TypoWarning,
)
from ._types import ConfigSettings as ConfigSettingsType
from ._types import Distribution as DistributionType
from ._types import SubprocessRunner as RunnerType
from ._util import check_dependency

__version__ = '1.2.1'

__all__ = [
    '__version__',
    'BuildBackendException',
    'BuildException',
    'BuildSystemTableValidationError',
    'check_dependency',
    'ConfigSettingsType',
    'DistributionType',
    'FailedProcessError',
    'ProjectBuilder',
    'RunnerType',
    'TypoWarning',
]

def __dir__() -> list[str]:
    return __all__

# Logging configuration
logger = logging.getLogger("pypacker")
logger.setLevel(logging.WARNING)

class NiceFormatter(logging.Formatter):
    FORMATS = {
        logging.DEBUG: "%(module)s -> %(funcName)s -> %(lineno)d: %(message)s",
        logging.INFO: "%(message)s",
        logging.WARNING: "WARNING: %(module)s: %(lineno)d: %(message)s",
        logging.ERROR: "ERROR: %(module)s: %(lineno)d: %(message)s",
        "DEFAULT": "%(message)s",
    }

    def __init__(self):
        super().__init__(fmt="%(levelno)d: %(msg)s", datefmt=None, style="%")

    def format(self, record):
        format_orig = self._style._fmt
        self._style._fmt = self.FORMATS.get(record.levelno, self.FORMATS["DEFAULT"])
        result = super().format(record)
        self._style._fmt = format_orig
        return result

logger_streamhandler = logging.StreamHandler()
logger_formatter = NiceFormatter()
logger_streamhandler.setFormatter(logger_formatter)
logger.addHandler(logger_streamhandler)


# -*- coding: utf-8 -*-
# Copyright 2024 The Orbit Authors. All Rights Reserved.
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

"""Core is shared by both `nlp` and `vision`."""

from official.core import actions
from official.core import base_task
from official.core import base_trainer
from official.core import config_definitions
from official.core import exp_factory
from official.core import export_base
from official.core import file_writers
from official.core import input_reader
from official.core import registry
from official.core import savedmodel_checkpoint_manager
from official.core import task_factory
from official.core import tf_example_builder
from official.core import tf_example_feature_key
from official.core import train_lib
from official.core import train_utils
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

"""Activations package definition."""
from official.modeling.activations.gelu import gelu
from official.modeling.activations.mish import mish
from official.modeling.activations.relu import relu6
from official.modeling.activations.sigmoid import hard_sigmoid
from official.modeling.activations.swish import hard_swish
from official.modeling.activations.swish import identity
from official.modeling.activations.swish import simple_swish
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

"""Hyperparams package definition."""
# pylint: disable=g-multiple-import
from official.modeling.hyperparams.base_config import *
from official.modeling.hyperparams.oneof import *
from official.modeling.hyperparams.params_dict import *

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

"""Optimization package definition."""

# pylint: disable=wildcard-import
from official.modeling.optimization.configs.learning_rate_config import *
from official.modeling.optimization.configs.optimization_config import *
from official.modeling.optimization.configs.optimizer_config import *
from official.modeling.optimization.ema_optimizer import ExponentialMovingAverage
from official.modeling.optimization.lr_schedule import *
from official.modeling.optimization.optimizer_factory import OptimizerFactory
from official.modeling.optimization.optimizer_factory import register_optimizer_cls
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

"""NLP Modeling Library.

This library provides a set of Keras primitives (`tf_keras.Layer` and
`tf_keras.Model`) that can be assembled into transformer-based models.
They are flexible, validated, interoperable, and both TF1 and TF2 compatible.
"""
from official.nlp.modeling import layers
from official.nlp.modeling import losses
from official.nlp.modeling import models
from official.nlp.modeling import networks
from official.nlp.modeling import ops
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

"""Layers are the fundamental building blocks for NLP models.

They can be used to assemble new `tf.keras` layers or models.
"""
# pylint: disable=wildcard-import

from official.nlp.modeling.layers import util
from official.nlp.modeling.layers.attention import *
from official.nlp.modeling.layers.bigbird_attention import BigBirdAttention
from official.nlp.modeling.layers.bigbird_attention import BigBirdMasks
from official.nlp.modeling.layers.block_diag_feedforward import BlockDiagFeedforward
from official.nlp.modeling.layers.block_sparse_attention import MultiHeadAttention as BlockSparseAttention
from official.nlp.modeling.layers.cls_head import *
from official.nlp.modeling.layers.factorized_embedding import FactorizedEmbedding
from official.nlp.modeling.layers.gated_feedforward import GatedFeedforward
from official.nlp.modeling.layers.gaussian_process import RandomFeatureGaussianProcess
from official.nlp.modeling.layers.kernel_attention import KernelAttention
from official.nlp.modeling.layers.kernel_attention import KernelMask
from official.nlp.modeling.layers.masked_lm import MaskedLM
from official.nlp.modeling.layers.masked_softmax import MaskedSoftmax
from official.nlp.modeling.layers.mat_mul_with_margin import MatMulWithMargin
from official.nlp.modeling.layers.mixing import FourierTransformLayer
from official.nlp.modeling.layers.mixing import HartleyTransformLayer
from official.nlp.modeling.layers.mixing import LinearTransformLayer
from official.nlp.modeling.layers.mixing import MixingMechanism
from official.nlp.modeling.layers.mobile_bert_layers import MobileBertEmbedding
from official.nlp.modeling.layers.mobile_bert_layers import MobileBertMaskedLM
from official.nlp.modeling.layers.mobile_bert_layers import MobileBertTransformer
from official.nlp.modeling.layers.moe import ExpertsChooseMaskedRouter
from official.nlp.modeling.layers.moe import FeedForwardExperts
from official.nlp.modeling.layers.moe import MoeLayer
from official.nlp.modeling.layers.moe import MoeLayerWithBackbone
from official.nlp.modeling.layers.multi_channel_attention import *
from official.nlp.modeling.layers.multi_query_attention import MultiHeadAttention as MultiQueryAttention
from official.nlp.modeling.layers.on_device_embedding import OnDeviceEmbedding
from official.nlp.modeling.layers.pack_optimization import PackBertEmbeddings
from official.nlp.modeling.layers.pack_optimization import StridedReZeroTransformer
from official.nlp.modeling.layers.pack_optimization import StridedTransformerEncoderBlock
from official.nlp.modeling.layers.pack_optimization import StridedTransformerScaffold
from official.nlp.modeling.layers.per_dim_scale_attention import PerDimScaleAttention
from official.nlp.modeling.layers.position_embedding import PositionEmbedding
from official.nlp.modeling.layers.position_embedding import RelativePositionBias
from official.nlp.modeling.layers.position_embedding import RelativePositionEmbedding
from official.nlp.modeling.layers.relative_attention import MultiHeadRelativeAttention
from official.nlp.modeling.layers.relative_attention import TwoStreamRelativeAttention
from official.nlp.modeling.layers.reuse_attention import ReuseMultiHeadAttention
from official.nlp.modeling.layers.reuse_transformer import ReuseTransformer
from official.nlp.modeling.layers.rezero_transformer import ReZeroTransformer
from official.nlp.modeling.layers.routing import *
from official.nlp.modeling.layers.self_attention_mask import *
from official.nlp.modeling.layers.spectral_normalization import *
from official.nlp.modeling.layers.talking_heads_attention import TalkingHeadsAttention
from official.nlp.modeling.layers.text_layers import BertPackInputs
from official.nlp.modeling.layers.text_layers import BertTokenizer
from official.nlp.modeling.layers.text_layers import FastWordpieceBertTokenizer
from official.nlp.modeling.layers.text_layers import SentencepieceTokenizer
from official.nlp.modeling.layers.tn_transformer_expand_condense import TNTransformerExpandCondense
from official.nlp.modeling.layers.transformer import Transformer
from official.nlp.modeling.layers.transformer import TransformerDecoderBlock
from official.nlp.modeling.layers.transformer_encoder_block import TransformerEncoderBlock
from official.nlp.modeling.layers.transformer_scaffold import TransformerScaffold
from official.nlp.modeling.layers.transformer_xl import TransformerXL
from official.nlp.modeling.layers.transformer_xl import TransformerXLBlock
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

"""Losses contains common loss computation used in NLP (subject to change)."""
from official.nlp.modeling.losses.weighted_sparse_categorical_crossentropy import loss as weighted_sparse_categorical_crossentropy_loss
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

"""Models are combinations of `tf.keras` layers and models that can be trained.

Several pre-built canned models are provided to train encoder networks.
These models are intended as both convenience functions and canonical examples.
"""
from official.nlp.modeling.models.bert_classifier import BertClassifier
from official.nlp.modeling.models.bert_pretrainer import *
from official.nlp.modeling.models.bert_span_labeler import BertSpanLabeler
from official.nlp.modeling.models.bert_token_classifier import BertTokenClassifier
from official.nlp.modeling.models.dual_encoder import DualEncoder
from official.nlp.modeling.models.electra_pretrainer import ElectraPretrainer
from official.nlp.modeling.models.seq2seq_transformer import *
from official.nlp.modeling.models.t5 import T5Transformer
from official.nlp.modeling.models.t5 import T5TransformerParams
from official.nlp.modeling.models.xlnet import XLNetClassifier
from official.nlp.modeling.models.xlnet import XLNetPretrainer
from official.nlp.modeling.models.xlnet import XLNetSpanLabeler
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

"""Networks are combinations of `tf.keras` layers (and possibly other networks).

They are `tf.keras` models that would not be trained alone. It encapsulates
common network structures like a transformer encoder into an easily
handled object with a standardized configuration.
"""
from official.nlp.modeling.networks.albert_encoder import AlbertEncoder
from official.nlp.modeling.networks.bert_encoder import BertEncoder
from official.nlp.modeling.networks.bert_encoder import BertEncoderV2
from official.nlp.modeling.networks.classification import Classification
from official.nlp.modeling.networks.encoder_scaffold import EncoderScaffold
from official.nlp.modeling.networks.fnet import FNet
from official.nlp.modeling.networks.funnel_transformer import FunnelTransformerEncoder
from official.nlp.modeling.networks.mobile_bert_encoder import MobileBERTEncoder
from official.nlp.modeling.networks.packed_sequence_embedding import PackedSequenceEmbedding
from official.nlp.modeling.networks.span_labeling import SpanLabeling
from official.nlp.modeling.networks.span_labeling import XLNetSpanLabeling
from official.nlp.modeling.networks.sparse_mixer import SparseMixer
from official.nlp.modeling.networks.xlnet_base import XLNetBase
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

"""Ops package definition."""
from official.nlp.modeling.ops.beam_search import sequence_beam_search
from official.nlp.modeling.ops.beam_search import SequenceBeamSearch
from official.nlp.modeling.ops.sampling_module import SamplingModule
from official.nlp.modeling.ops.segment_extractor import get_next_sentence_labels
from official.nlp.modeling.ops.segment_extractor import get_sentence_order_labels
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

"""TensorFlow Models NLP Tasks."""
# pylint: disable=g-multiple-import
from official.nlp.tasks.electra_task import ElectraPretrainConfig, ElectraPretrainTask
from official.nlp.tasks.masked_lm import MaskedLMConfig, MaskedLMTask
from official.nlp.tasks.question_answering import QuestionAnsweringConfig, QuestionAnsweringTask
from official.nlp.tasks.sentence_prediction import SentencePredictionConfig, SentencePredictionTask
from official.nlp.tasks.tagging import TaggingConfig, TaggingTask
from official.nlp.tasks.translation import TranslationConfig, TranslationTask
# Copyright 2024 The Orbit Authors. All Rights Reserved.
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

"""Defines an "action" abstraction for use with `orbit.Controller`.

"Actions" are simply arbitrary callables that are applied by the `Controller`
to the output of train steps (after each inner loop of `steps_per_loop` steps)
or an evaluation. This provides a hook mechanism, enabling things like reporting
metrics to Vizier, model exporting, additional logging, etc.

The basic `Action` abstraction (just a type alias) is defined in the
`controller` module. This `actions` module adds a `ConditionalAction` utility
class to make it easy to trigger actions conditionally based on reusable
predicates, as well as a small handful of predefined conditions/actions (in
particular, a `NewBestMetric` condition and an `ExportSavedModel` action).

One example of using actions to do metric-conditional export:

    new_best_metric = orbit.actions.NewBestMetric('accuracy')
    export_action = orbit.actions.ConditionalAction(
        condition=lambda x: x['accuracy'] > 0.9 and new_best_metric(x),
        action=orbit.actions.ExportSavedModel(
            model,
            orbit.actions.ExportFileManager(
                base_name=f'{FLAGS.model_dir}/saved_model',
                next_id_fn=trainer.global_step.numpy),
            signatures=model.infer))

    controller = orbit.Controller(
        strategy=strategy,
        trainer=trainer,
        evaluator=evaluator,
        eval_actions=[export_action],
        global_step=trainer.global_step,
        steps_per_loop=FLAGS.steps_per_loop,
        checkpoint_manager=checkpoint_manager,
        summary_interval=1000)

Note: In multi-client settings where each client runs its own `Controller`
instance, some care should be taken in deciding which clients should run certain
actions. Isolating actions to an individual client (say client 0) can be
achieved using `ConditionalAction` as follows:

    client_0_actions = orbit.actions.ConditionalAction(
        condition=lambda _: client_id() == 0,
        action=[
            ...
        ])

In particular, the `NewBestMetric` condition may be used in multi-client
settings if all clients are guaranteed to compute the same metric (ensuring this
is up to client code, not Orbit). However, when saving metrics it may be helpful
to avoid unnecessary writes by setting the `write_value` parameter to `False`
for most clients.
"""

from orbit.actions.conditional_action import ConditionalAction

from orbit.actions.export_saved_model import ExportFileManager
from orbit.actions.export_saved_model import ExportSavedModel

from orbit.actions.new_best_metric import JSONPersistedValue
from orbit.actions.new_best_metric import NewBestMetric

from orbit.actions.save_checkpoint_if_preempted import SaveCheckpointIfPreempted

# Copyright 2024 The Orbit Authors. All Rights Reserved.
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

"""Defines exported symbols for the `orbit` package."""

from orbit import actions
# Internal import orbit.
from orbit import utils

from orbit.controller import Action
from orbit.controller import Controller

from orbit.runner import AbstractEvaluator
from orbit.runner import AbstractTrainer

from orbit.standard_runner import StandardEvaluator
from orbit.standard_runner import StandardEvaluatorOptions
from orbit.standard_runner import StandardTrainer
from orbit.standard_runner import StandardTrainerOptions
# Copyright 2024 The Orbit Authors. All Rights Reserved.
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

"""Defines exported symbols for the `orbit.utils` package."""

from orbit.utils.common import create_global_step
from orbit.utils.common import get_value
from orbit.utils.common import make_distributed_dataset

from orbit.utils.epoch_helper import EpochHelper

from orbit.utils.loop_fns import create_loop_fn
from orbit.utils.loop_fns import create_tf_while_loop_fn
from orbit.utils.loop_fns import LoopFnWithSummaries

from orbit.utils.summary_manager import SummaryManager
from orbit.utils.summary_manager_interface import SummaryManagerInterface

from orbit.utils.tpu_summaries import OptionalSummariesFunction
# Copyright 2017 The TensorFlow Authors All Rights Reserved.
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
# ==============================================================================

from datasets import fsns
from datasets import fsns_test

__all__ = [fsns, fsns_test]
# Copyright 2024 The Orbit Authors. All Rights Reserved.
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

"""Defines an "action" abstraction for use with `orbit.Controller`.

"Actions" are simply arbitrary callables that are applied by the `Controller`
to the output of train steps (after each inner loop of `steps_per_loop` steps)
or an evaluation. This provides a hook mechanism, enabling things like reporting
metrics to Vizier, model exporting, additional logging, etc.

The basic `Action` abstraction (just a type alias) is defined in the
`controller` module. This `actions` module adds a `ConditionalAction` utility
class to make it easy to trigger actions conditionally based on reusable
predicates, as well as a small handful of predefined conditions/actions (in
particular, a `NewBestMetric` condition and an `ExportSavedModel` action).

One example of using actions to do metric-conditional export:

    new_best_metric = orbit.actions.NewBestMetric('accuracy')
    export_action = orbit.actions.ConditionalAction(
        condition=lambda x: x['accuracy'] > 0.9 and new_best_metric(x),
        action=orbit.actions.ExportSavedModel(
            model,
            orbit.actions.ExportFileManager(
                base_name=f'{FLAGS.model_dir}/saved_model',
                next_id_fn=trainer.global_step.numpy),
            signatures=model.infer))

    controller = orbit.Controller(
        strategy=strategy,
        trainer=trainer,
        evaluator=evaluator,
        eval_actions=[export_action],
        global_step=trainer.global_step,
        steps_per_loop=FLAGS.steps_per_loop,
        checkpoint_manager=checkpoint_manager,
        summary_interval=1000)

Note: In multi-client settings where each client runs its own `Controller`
instance, some care should be taken in deciding which clients should run certain
actions. Isolating actions to an individual client (say client 0) can be
achieved using `ConditionalAction` as follows:

    client_0_actions = orbit.actions.ConditionalAction(
        condition=lambda _: client_id() == 0,
        action=[
            ...
        ])

In particular, the `NewBestMetric` condition may be used in multi-client
settings if all clients are guaranteed to compute the same metric (ensuring this
is up to client code, not Orbit). However, when saving metrics it may be helpful
to avoid unnecessary writes by setting the `write_value` parameter to `False`
for most clients.
"""

from orbit.actions.conditional_action import ConditionalAction

from orbit.actions.export_saved_model import ExportFileManager
from orbit.actions.export_saved_model import ExportSavedModel

from orbit.actions.new_best_metric import JSONPersistedValue
from orbit.actions.new_best_metric import NewBestMetric

from orbit.actions.save_checkpoint_if_preempted import SaveCheckpointIfPreempted


"""
Created on Thu Aug 15 12:29:20 2024

@author: Ian Malloy
"""

