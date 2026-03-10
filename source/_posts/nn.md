title: "From MLPs to WaveNet: Why Squashing Information Kills Learning"
date: 2026-02-14 12:00:00
tags:
  - Neural Network
  - Deep Learning
categories:
  - 技术
---

I was watching Karpathy's tutorial nn-zero-to-hero.

When moving from a simple Multi-Layer Perceptron (MLP) language model to a WaveNet (Convolutional) architecture, a fundamental question arises: **Why do we need a new layer type?**

<!-- more -->

Mathematically, an MLP is a "Universal Function Approximator." Theoretically, if you make it wide enough, it can represent any function. So, why does Karpathy suggest that feeding a whole context into a linear layer "squashes" information, and that WaveNet is better?

## 1. The Hypothesis: Is it Floating Point Precision?
**The initial thought:** Since computers have limited floating-point precision (rounding errors), perhaps a massive linear layer loses information purely because of calculation limits.

**The Reality:** this isn't the main reason. I'm too naive. Neural networks are actually surprisingly robust to low precision (often training in `float16` or `int8`). The problem isn't the *precision* of the numbers; it’s the **structure** of the processing.

## 2. The Real Problem: The "Soup" vs. The "Sandwich"
When you feed a sequence of characters (e.g., 8 tokens) into a single, flat Linear Layer, you are performing a global dot product.

$y = w_1x_1 + w_2x_2 + \dots + w_nx_n$

This leads to two major issues:

### A. The Cancellation (Interference)
A Linear Layer is additive. If Feature A contributes a positive value and Feature B contributes a negative value, they might sum to zero.
*   **Result:** The unique identity of those features is lost. The next layer cannot look back and see what inputs created that zero. The signal has "canceled out."
*   **The "Squash":** You are smashing distinct spatial information into a single scalar value too early.

### B. Loss of Structure
*   **MLP Approach:** Like throwing a steak, potatoes, and wine into a blender. You get a soup. The next layer (the chef) cannot reconstruct the dinner because the spatial relationships are gone.
*   **WaveNet Approach:** Like an assembly line.
    1.  **Layer 1:** Process immediate neighbors (steak + seasoning).
    2.  **Layer 2:** Process groups of neighbors (steak + potatoes).
    3.  **Layer 3:** Combine high-level concepts.
    This preserves the hierarchy of information.

## 3. The Core Insight: Architecture as "Preset Weights"
This is the critical realization.

**A WaveNet (or Convolution) is mathematically just a Linear Layer, but with a specific constraint.**

If you look at the weight matrix of a standard MLP, every weight is learned from scratch. The optimizer has to figure out everything.
$$
\begin{bmatrix}
w_{1,1} & w_{1,2} & w_{1,3} \\
w_{2,1} & w_{2,2} & w_{2,3} \\
\dots & \dots & \dots
\end{bmatrix}
$$

However, a Convolutional layer can be viewed as an MLP where we have **manually preset** the weights:
1.  **Sparsity (Zeros):** We force weights connecting distant characters (e.g., char 1 and char 8) to be **0**. We tell the model: *"Don't waste time trying to find a relationship here yet."*
2.  **Weight Sharing:** We force the weights at position 1 to be identical to the weights at position 2. We tell the model: *"The logic for finding a pattern is the same everywhere."*

**Conclusion:** Advanced architectures are just MLPs where we have "hard-coded" a better starting strategy to make optimization (training) easier.

## 4. The Future: Mechanistic Interpretability
If specific architectures are just "hard-coded patterns," can we discover new ones?

This connects to the work of **Chris Olah (Anthropic)**.
*   We train massive, messy Transformers (which look like dense MLPs).
*   We "X-ray" them to see what circuits they actually learn (e.g., Induction Heads).
*   We realize they are trying to create sparse patterns inside their dense layers.
*   **The Goal:** Inspire the next generation of architectures (like State Space Models or Sparse Attention) by hard-coding the patterns that current models are struggling to learn from scratch.

***

**Summary:** We don't use WaveNet because the math is fancier. We use it to restrict the search space, preventing the model from drowning in its own freedom, and forcing it to process information step-by-step.