# PHISH-X — Numerical Methods Research

## 1. Purpose

This document presents a technical overview of two numerical optimization methods used in machine learning:

- Gradient Descent
- Newton's Method

The objective is to understand how these methods minimize a loss function and how they can be applied to Logistic Regression in the PHISH-X phishing URL detection project.

## 2. Introduction to Numerical Optimization

Machine learning models often require numerical optimization to find parameters that minimize a loss function.

In Logistic Regression, the model learns weights and a bias to estimate the probability that a URL belongs to a particular class.

The optimization process aims to find parameter values that minimize the selected loss function.

Two methods considered in this project are Gradient Descent and Newton's Method.

## 3. Gradient Descent

### 3.1 Definition

Gradient Descent is an iterative optimization algorithm that updates model parameters in the direction opposite to the gradient of the loss function.

The gradient indicates the direction of the steepest increase in the loss. Moving in the opposite direction is intended to reduce the loss.

### 3.2 Update Rule

The parameter update rule is:

\[
\theta_{new} = \theta_{old} - \alpha \nabla J(\theta)
\]

Where:

- \(\theta\): Model parameters.
- \(\alpha\): Learning rate.
- \(J(\theta)\): Loss function.
- \(\nabla J(\theta)\): Gradient of the loss function.

### 3.3 How It Works

1. Initialize the model parameters.
2. Calculate predictions using the current parameters.
3. Calculate the loss.
4. Compute the gradient of the loss.
5. Update the parameters using the learning rate.
6. Repeat until a stopping condition is reached.

### 3.4 Advantages

- Relatively simple to implement.
- Does not require calculating the Hessian matrix.
- Can be applied to large datasets using batch or mini-batch approaches.
- Requires less memory than methods that store a full Hessian matrix.

### 3.5 Limitations

- The learning rate must be selected carefully.
- A very high learning rate may cause unstable updates or prevent convergence.
- A very low learning rate may result in slow convergence.
- The number of iterations required may be large.
- Convergence behavior depends on the loss function and its properties.

## 4. Newton's Method

### 4.1 Definition

Newton's Method is an optimization algorithm that uses both the gradient and the second derivatives of a function to update its parameters.

The second derivatives describe the curvature of the loss function and are represented by the Hessian matrix.

### 4.2 Update Rule

The parameter update rule is:

\[
\theta_{new} = \theta_{old} - H(\theta)^{-1}\nabla J(\theta)
\]

Where:

- \(\theta\): Model parameters.
- \(J(\theta)\): Loss function.
- \(\nabla J(\theta)\): Gradient of the loss function.
- \(H(\theta)\): Hessian matrix of second derivatives.
- \(H(\theta)^{-1}\): Inverse Hessian, when it exists.

### 4.3 How It Works

1. Initialize the model parameters.
2. Calculate predictions and the loss.
3. Compute the gradient.
4. Compute the Hessian matrix.
5. Solve the Newton update equation.
6. Update the parameters.
7. Repeat until a stopping condition is reached.

In practice, solving a linear system is generally preferred over explicitly calculating the inverse Hessian.

### 4.4 Advantages

- Uses second-order information about the loss function.
- Can converge rapidly near a suitable solution under appropriate conditions.
- Does not require selecting a conventional learning rate in its basic form.
- Can be effective for smaller optimization problems.

### 4.5 Limitations

- Calculating the Hessian can be computationally expensive.
- Storing and solving systems involving the Hessian can require significant memory and computation.
- The Hessian may be singular or poorly conditioned.
- A Newton update does not always guarantee a decrease in the loss without suitable conditions or modifications.
- It may be impractical for models with a very large number of parameters.

## 5. Comparison Between the Two Methods

| Aspect | Gradient Descent | Newton's Method |
|---|---|---|
| Derivative information | First-order | Second-order |
| Main information used | Gradient | Gradient and Hessian |
| Learning rate | Usually required | Not required in basic form |
| Computational cost per iteration | Generally lower | Generally higher |
| Memory requirements | Generally lower | Can be high due to Hessian |
| Convergence | May require many iterations | Can be fast near a suitable solution |
| Large parameter spaces | Often more practical | Can become expensive |
| Main limitation | Learning rate and iteration count | Hessian computation and stability |

Neither method is universally better. Their performance depends on the loss function, dataset size, parameter count, and implementation.

## 6. Application to Logistic Regression in PHISH-X

PHISH-X uses Logistic Regression to classify URLs into two classes:

- Class 0: Phishing.
- Class 1: Legitimate.

Logistic Regression estimates the probability of a class using the sigmoid function:

\[
\sigma(z) = \frac{1}{1 + e^{-z}}
\]

Where:

\[
z = w^T x + b
\]

The model parameters are the weight vector \(w\) and bias \(b\).

The binary cross-entropy loss can be expressed as:

\[
J(w,b) = -\frac{1}{m}\sum_{i=1}^{m}
[y_i\log(p_i)+(1-y_i)\log(1-p_i)]
\]

Where:

- \(m\): Number of training samples.
- \(y_i\): Actual binary target.
- \(p_i\): Predicted probability for the positive class.

For the mathematical loss formulation, the positive class must be defined consistently. Since PHISH-X uses class 0 for Phishing and class 1 for Legitimate, the target encoding must be handled correctly when calculating probabilities and metrics.

Both Gradient Descent and Newton's Method can be used to optimize Logistic Regression parameters by minimizing the selected loss function.

## 7. Experimental Comparison Considerations

A fair comparison between the two methods should use:

1. The same training dataset.
2. The same feature set and preprocessing steps.
3. The same loss function.
4. Consistent parameter initialization where applicable.
5. A clearly defined stopping criterion.
6. The same evaluation metrics.

Recommended measurements include:

- Final training loss.
- Number of iterations.
- Execution time.
- Convergence behavior.
- Classification accuracy.
- Precision.
- Recall.
- F1-score.

The final test set should not be used to optimize model parameters or select hyperparameters.

The host-based group split should be used as the primary evaluation strategy in PHISH-X.

## 8. Important Implementation Considerations

- Numerical features should be scaled when appropriate, using transformations fitted on the training data only.
- The learning rate for Gradient Descent should be selected through training experiments.
- Newton's Method should handle singular or poorly conditioned Hessian matrices safely.
- Regularization may be needed to reduce overfitting.
- Both methods should use the same objective function for a meaningful comparison.
- Actual experimental results must be reported separately from theoretical expectations.

## 9. Conclusion

Gradient Descent and Newton's Method are two important numerical optimization approaches.

Gradient Descent uses first-order information and generally has lower computational cost per iteration. Newton's Method uses second-order information and may converge rapidly near a suitable solution, but its Hessian computation can be expensive.

In PHISH-X, both methods provide a basis for studying the optimization of Logistic Regression.

The final choice or comparison should be supported by experimental results rather than theoretical assumptions alone.

## 10. References

1. Bishop, C. M. (2006). *Pattern Recognition and Machine Learning*. Springer.
2. Goodfellow, I., Bengio, Y., & Courville, A. (2016). *Deep Learning*. MIT Press.
3. Boyd, S., & Vandenberghe, L. (2004). *Convex Optimization*. Cambridge University Press.
4. Nocedal, J., & Wright, S. J. (2006). *Numerical Optimization* (2nd ed.). Springer.