<div align="center">
  <img src="https://storage.googleapis.com/tf_model_garden/tf_model_garden_logo.png">
</div>

[![Python](https://img.shields.io/pypi/pyversions/tensorflow.svg?style=plastic)](https://badge.fury.io/py/tensorflow)
[![tf-models-official PyPI](https://badge.fury.io/py/tf-models-official.svg)](https://badge.fury.io/py/tf-models-official)


# Welcome to the Model Garden for TensorFlow

The TensorFlow Model Garden is a repository with a number of different
implementations of state-of-the-art (SOTA) models and modeling solutions for
TensorFlow users. We aim to demonstrate the best practices for modeling so that
TensorFlow users can take full advantage of TensorFlow for their research and
product development.

To improve the transparency and reproducibility of our models, training logs on
[TensorBoard.dev](https://tensorboard.dev) are also provided for models to the
extent possible though not all models are suitable.

| Directory | Description |
|-----------|-------------|
| [official](official) | • A collection of example implementations for SOTA models using the latest TensorFlow 2's high-level APIs<br />• Officially maintained, supported, and kept up to date with the latest TensorFlow 2 APIs by TensorFlow<br />• Reasonably optimized for fast performance while still being easy to read<br /> For more details on the capabilities, check the guide on the [Model-garden](https://www.tensorflow.org/tfmodels)|
| [research](research) | • A collection of research model implementations in TensorFlow 1 or 2 by researchers<br />• Maintained and supported by researchers |
| [community](community) | • A curated list of the GitHub repositories with machine learning models and implementations powered by TensorFlow 2 |
| [orbit](orbit) | • A flexible and lightweight library that users can easily use or fork when writing customized training loop code in TensorFlow 2.x. It seamlessly integrates with `tf.distribute` and supports running on different device types (CPU, GPU, and TPU). |

## Installation

To install the current release of tensorflow-models, please follow any one of the methods described below.

#### Method 1: Install the TensorFlow Model Garden pip package

<details>

**tf-models-official** is the stable Model Garden package. Please check out the [releases](https://github.com/tensorflow/models/releases) to see what are available modules.

pip3 will install all models and dependencies automatically.

```shell
pip3 install tf-models-official
```

Please check out our examples:
  - [basic library import](https://github.com/tensorflow/models/blob/master/tensorflow_models/tensorflow_models_pypi.ipynb)
  - [nlp model building](https://github.com/tensorflow/models/blob/master/docs/nlp/index.ipynb)
to learn how to use a PIP package.

Note that **tf-models-official** may not include the latest changes in the master branch of this
github repo. To include latest changes, you may install **tf-models-nightly**,
which is the nightly Model Garden package created daily automatically.

```shell
pip3 install tf-models-nightly
```

</details>


#### Method 2: Clone the source

<details>

1. Clone the GitHub repository:

```shell
git clone https://github.com/tensorflow/models.git
```

2. Add the top-level ***/models*** folder to the Python path.

```shell
export PYTHONPATH=$PYTHONPATH:/path/to/models
```

If you are using in a Windows environment, you may need to use the following command with PowerShell:
```shell
$env:PYTHONPATH += ":\path\to\models"
```

If you are using a Colab notebook, please set the Python path with os.environ.

```python
import os
os.environ['PYTHONPATH'] += ":/path/to/models"
```

3. Install other dependencies

```shell
pip3 install --user -r models/official/requirements.txt
```

Finally, if you are using nlp packages, please also install
**tensorflow-text-nightly**:

```shell
pip3 install tensorflow-text-nightly
```

</details>


## Announcements

Please check [this page](https://github.com/tensorflow/models/wiki/Announcements) for recent announcements.

## Contributions

[![help wanted:paper implementation](https://img.shields.io/github/issues/tensorflow/models/help%20wanted%3Apaper%20implementation)](https://github.com/tensorflow/models/labels/help%20wanted%3Apaper%20implementation)

If you want to contribute, please review the [contribution guidelines](https://github.com/tensorflow/models/wiki/How-to-contribute).

## License

[Apache License 2.0](LICENSE)

## Citing TensorFlow Model Garden

If you use TensorFlow Model Garden in your research, please cite this repository.

```
@misc{tensorflowmodelgarden2020,
  author = {Hongkun Yu, Chen Chen, Xianzhi Du, Yeqing Li, Abdullah Rashwan, Le Hou, Pengchong Jin, Fan Yang,
            Frederick Liu, Jaeyoun Kim, and Jing Li},
  title = {{TensorFlow Model Garden}},
  howpublished = {\url{https://github.com/tensorflow/models}},
  year = {2020}
}
```
![Logo](https://storage.googleapis.com/tf_model_garden/tf_model_garden_logo.png)

# TensorFlow Community Models

This repository provides a curated list of the GitHub repositories with machine learning models and implementations powered by TensorFlow 2.

**Note**: Contributing companies or individuals are responsible for maintaining their repositories.

## Computer Vision

### Image Recognition

| Model | Paper | Features | Maintainer |
|-------|-------|----------|------------|
| [DenseNet 169](https://github.com/IntelAI/models/tree/master/benchmarks/image_recognition/tensorflow/densenet169) | [Densely Connected Convolutional Networks](https://arxiv.org/pdf/1608.06993) | • FP32 Inference | [Intel](https://github.com/IntelAI) |
| [Inception V3](https://github.com/IntelAI/models/tree/master/benchmarks/image_recognition/tensorflow/inceptionv3) | [Rethinking the Inception Architecture<br/>for Computer Vision](https://arxiv.org/pdf/1512.00567.pdf) | • Int8 Inference<br/>• FP32 Inference | [Intel](https://github.com/IntelAI) |
| [Inception V4](https://github.com/IntelAI/models/tree/master/benchmarks/image_recognition/tensorflow/inceptionv4) | [Inception-v4, Inception-ResNet and the Impact<br/>of Residual Connections on Learning](https://arxiv.org/pdf/1602.07261) | • Int8 Inference<br/>• FP32 Inference | [Intel](https://github.com/IntelAI) |
| [MobileNet V1](https://github.com/IntelAI/models/tree/master/benchmarks/image_recognition/tensorflow/mobilenet_v1) | [MobileNets: Efficient Convolutional Neural Networks<br/>for Mobile Vision Applications](https://arxiv.org/pdf/1704.04861) | • Int8 Inference<br/>• FP32 Inference | [Intel](https://github.com/IntelAI) |
| [ResNet 101](https://github.com/IntelAI/models/tree/master/benchmarks/image_recognition/tensorflow/resnet101) | [Deep Residual Learning for Image Recognition](https://arxiv.org/pdf/1512.03385) | • Int8 Inference<br/>• FP32 Inference | [Intel](https://github.com/IntelAI) |
| [ResNet 50](https://github.com/IntelAI/models/tree/master/benchmarks/image_recognition/tensorflow/resnet50) | [Deep Residual Learning for Image Recognition](https://arxiv.org/pdf/1512.03385) | • Int8 Inference<br/>• FP32 Inference | [Intel](https://github.com/IntelAI) |
| [ResNet 50v1.5](https://github.com/IntelAI/models/tree/master/benchmarks/image_recognition/tensorflow/resnet50v1_5) | [Deep Residual Learning for Image Recognition](https://arxiv.org/pdf/1512.03385) | • Int8 Inference<br/>• FP32 Inference<br/>• FP32 Training | [Intel](https://github.com/IntelAI) |
| EfficientNet [v1](https://github.com/NVIDIA/DeepLearningExamples/tree/master/TensorFlow2/Classification/ConvNets/efficientnet_v1) [v2](https://github.com/NVIDIA/DeepLearningExamples/tree/master/TensorFlow2/Classification/ConvNets/efficientnet_v2) | [EfficientNet: Rethinking Model Scaling for Convolutional Neural Networks](https://arxiv.org/pdf/1905.11946.pdf) | • Automatic mixed precision<br/>• Horovod Multi-GPU training (NCCL)<br/>• Multi-node training on a Pyxis/Enroot Slurm cluster<br/>• XLA | [NVIDIA](https://github.com/NVIDIA) |

### Object Detection

| Model | Paper | Features | Maintainer |
|-------|-------|----------|------------|
| [R-FCN](https://github.com/IntelAI/models/tree/master/benchmarks/object_detection/tensorflow/rfcn) | [R-FCN: Object Detection<br/>via Region-based Fully Convolutional Networks](https://arxiv.org/pdf/1605.06409) | • Int8 Inference<br/>• FP32 Inference | [Intel](https://github.com/IntelAI) |
| [SSD-MobileNet](https://github.com/IntelAI/models/tree/master/benchmarks/object_detection/tensorflow/ssd-mobilenet) | [MobileNets: Efficient Convolutional Neural Networks<br/>for Mobile Vision Applications](https://arxiv.org/pdf/1704.04861) | • Int8 Inference<br/>• FP32 Inference | [Intel](https://github.com/IntelAI) |
| [SSD-ResNet34](https://github.com/IntelAI/models/tree/master/benchmarks/object_detection/tensorflow/ssd-resnet34) | [SSD: Single Shot MultiBox Detector](https://arxiv.org/pdf/1512.02325) | • Int8 Inference<br/>• FP32 Inference<br/>• FP32 Training | [Intel](https://github.com/IntelAI) |

### Segmentation

| Model | Paper | Features | Maintainer |
|-------|-------|----------|------------|
| [Mask R-CNN](https://github.com/NVIDIA/DeepLearningExamples/tree/master/TensorFlow2/Segmentation/MaskRCNN) | [Mask R-CNN](https://arxiv.org/abs/1703.06870) | • Automatic Mixed Precision<br/>• Multi-GPU training support with Horovod<br/>• TensorRT | [NVIDIA](https://github.com/NVIDIA) |
| [U-Net Medical Image Segmentation](https://github.com/NVIDIA/DeepLearningExamples/tree/master/TensorFlow2/Segmentation/UNet_Medical) | [U-Net: Convolutional Networks for Biomedical Image Segmentation](https://arxiv.org/abs/1505.04597) | • Automatic Mixed Precision<br/>• Multi-GPU training support with Horovod<br/>• TensorRT | [NVIDIA](https://github.com/NVIDIA) |

## Natural Language Processing

| Model | Paper | Features | Maintainer |
|-------|-------|----------|------------|
| [BERT](https://github.com/IntelAI/models/tree/master/benchmarks/language_modeling/tensorflow/bert_large) | [BERT: Pre-training of Deep Bidirectional Transformers<br/>for Language Understanding](https://arxiv.org/pdf/1810.04805) | • FP32 Inference<br/>• FP32 Training | [Intel](https://github.com/IntelAI) |
| [BERT](https://github.com/NVIDIA/DeepLearningExamples/tree/master/TensorFlow2/LanguageModeling/BERT) | [BERT: Pre-training of Deep Bidirectional Transformers for Language Understanding](https://arxiv.org/pdf/1810.04805) | • Horovod Multi-GPU<br/>• Multi-node with Horovod and Pyxis/Enroot Slurm cluster<br/>• XLA<br/>• Automatic mixed precision<br/>• LAMB | [NVIDIA](https://github.com/NVIDIA) |
| [ELECTRA](https://github.com/NVIDIA/DeepLearningExamples/tree/master/TensorFlow2/LanguageModeling/ELECTRA) | [ELECTRA: Pre-training Text Encoders as Discriminators Rather Than Generators](https://openreview.net/forum?id=r1xMH1BtvB) | • Automatic Mixed Precision<br/>• Multi-GPU training support with Horovod<br/>• Multi-node training on a Pyxis/Enroot Slurm cluster | [NVIDIA](https://github.com/NVIDIA) |
| [GNMT](https://github.com/IntelAI/models/tree/master/benchmarks/language_translation/tensorflow/mlperf_gnmt) | [Google’s Neural Machine Translation System:<br/>Bridging the Gap between Human and Machine Translation](https://arxiv.org/pdf/1609.08144) | • FP32 Inference | [Intel](https://github.com/IntelAI) |
| [Transformer-LT (Official)](https://github.com/IntelAI/models/tree/master/benchmarks/language_translation/tensorflow/transformer_lt_official) | [Attention Is All You Need](https://arxiv.org/pdf/1706.03762) | • FP32 Inference | [Intel](https://github.com/IntelAI) |
| [Transformer-LT (MLPerf)](https://github.com/IntelAI/models/tree/master/benchmarks/language_translation/tensorflow/transformer_mlperf) | [Attention Is All You Need](https://arxiv.org/pdf/1706.03762) | • FP32 Training | [Intel](https://github.com/IntelAI) |

## Recommendation Systems

| Model | Paper | Features | Maintainer |
|-------|-------|----------|------------|
| [Wide & Deep](https://github.com/IntelAI/models/tree/master/benchmarks/recommendation/tensorflow/wide_deep_large_ds) | [Wide & Deep Learning for Recommender Systems](https://arxiv.org/pdf/1606.07792) | • FP32 Inference<br/>• FP32 Training | [Intel](https://github.com/IntelAI) |
| [Wide & Deep](https://github.com/NVIDIA/DeepLearningExamples/tree/master/TensorFlow2/Recommendation/WideAndDeep) | [Wide & Deep Learning for Recommender Systems](https://arxiv.org/pdf/1606.07792) | • Automatic mixed precision<br/>• Multi-GPU training support with Horovod<br/>• XLA | [NVIDIA](https://github.com/NVIDIA) |
| [DLRM](https://github.com/NVIDIA/DeepLearningExamples/tree/master/TensorFlow2/Recommendation/DLRM) | [Deep Learning Recommendation Model for Personalization and Recommendation Systems](https://arxiv.org/pdf/1906.00091.pdf) | • Automatic Mixed Precision<br/>• Hybrid-parallel multiGPU training using Horovod all2all<br/>• Multinode training for Pyxis/Enroot Slurm clusters<br/>• XLA<br/>• Criteo dataset preprocessing with Spark on GPU | [NVIDIA](https://github.com/NVIDIA) |

## Contributions

If you want to contribute, please review the [contribution guidelines](https://github.com/tensorflow/models/wiki/How-to-contribute).
