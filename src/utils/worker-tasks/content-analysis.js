/**
 * Content Analysis Worker Task
 * Performs CPU-intensive content analysis for moderation
 */

const crypto = require('crypto');

/**
 * Execute the content analysis task
 * @param {Object} data - Task input data
 * @param {string} data.content - Content to analyze
 * @param {Object} data.options - Analysis options
 * @param {Object} context - Execution context
 * @returns {Object} Analysis results
 */
async function execute(data = {}, context = {}) {
    try {
        // Validate input
        if (!data || !data.content) {
            throw new Error('Content is required for analysis');
        }

        const content = data.content;
        const options = data.options || {};

        // Default options
        const analysisOptions = {
            checkProfanity: options.checkProfanity !== false,
            checkToxicity: options.checkToxicity !== false,
            checkSensitiveData: options.checkSensitiveData !== false,
            checkSpam: options.checkSpam !== false,
            sensitivityLevel: options.sensitivityLevel || 'medium',
            language: options.language || 'en',
            ...options
        };

        // Start timing the analysis
        const startTime = process.hrtime.bigint();

        // Perform content analysis
        const results = await analyzeContent(content, analysisOptions);

        // Calculate processing time
        const endTime = process.hrtime.bigint();
        const processingTime = Number(endTime - startTime) / 1_000_000; // Convert to ms

        // Return results with metadata
        return {
            results,
            meta: {
                processingTime,
                contentLength: content.length,
                contentHash: crypto.createHash('sha256').update(content).digest('hex').substring(0, 16),
                options: analysisOptions,
                workerId: context.workerId || 'unknown'
            }
        };
    } catch (error) {
        console.error('Error in content analysis task:', error);
        throw new Error(`Content analysis failed: ${error.message}`);
    }
}

/**
 * Analyze content for moderation purposes
 * @param {string} content - Content to analyze
 * @param {Object} options - Analysis options
 * @returns {Promise<Object>} Analysis results
 */
async function analyzeContent(content, options) {
    // Initialize results object
    const results = {
        isViolation: false,
        categories: {},
        scores: {},
        explanation: '',
        suggestedAction: 'none',
        severity: 'none',
        confidence: 0
    };

    // Perform profanity check if enabled
    if (options.checkProfanity) {
        const profanityResults = checkProfanity(content, options);
        results.categories.profanity = profanityResults.detected;
        results.scores.profanity = profanityResults.score;

        if (profanityResults.detected && profanityResults.score > 0.7) {
            results.isViolation = true;
            results.explanation += `Profanity detected (${profanityResults.words.join(', ')}). `;
            results.severity = profanityResults.score > 0.9 ? 'severe' : 'moderate';
        }
    }

    // Perform toxicity check if enabled
    if (options.checkToxicity) {
        const toxicityResults = checkToxicity(content, options);
        results.categories.toxicity = toxicityResults.detected;
        results.scores.toxicity = toxicityResults.score;

        if (toxicityResults.detected) {
            results.isViolation = true;
            results.explanation += `Toxic content detected (${toxicityResults.type}). `;
            results.severity = toxicityResults.score > 0.8 ? 'severe' : 'moderate';
        }
    }

    // Perform sensitive data check if enabled
    if (options.checkSensitiveData) {
        const sensitiveResults = checkSensitiveData(content, options);
        results.categories.sensitiveData = sensitiveResults.detected;
        results.scores.sensitiveData = sensitiveResults.score;

        if (sensitiveResults.detected) {
            results.isViolation = true;
            results.explanation += `Sensitive data detected (${sensitiveResults.type}). `;
            results.severity = 'severe';
        }
    }

    // Perform spam check if enabled
    if (options.checkSpam) {
        const spamResults = checkSpam(content, options);
        results.categories.spam = spamResults.detected;
        results.scores.spam = spamResults.score;

        if (spamResults.detected) {
            results.isViolation = true;
            results.explanation += 'Spam content detected. ';
            results.severity = spamResults.score > 0.9 ? 'moderate' : 'low';
        }
    }

    // Calculate overall confidence score
    const scoreValues = Object.values(results.scores);
    results.confidence = scoreValues.length > 0
        ? scoreValues.reduce((sum, score) => sum + score, 0) / scoreValues.length
        : 0;

    // Determine suggested action based on severity and confidence
    if (results.isViolation) {
        if (results.severity === 'severe' && results.confidence > 0.8) {
            results.suggestedAction = 'delete_and_warn';
        } else if (results.severity === 'moderate' && results.confidence > 0.7) {
            results.suggestedAction = 'warn';
        } else {
            results.suggestedAction = 'flag_for_review';
        }
    }

    return results;
}

/**
 * Check content for profanity
 * @param {string} content - Content to check
 * @param {Object} options - Check options
 * @returns {Object} Profanity check results
 */
function checkProfanity(content, options) {
    // This is a simplified implementation
    // In a real application, this would use a comprehensive profanity dictionary
    // or a machine learning model

    const profanityList = [
        'badword1', 'badword2', 'badword3',
        // Add more profanity words here
    ];

    const sensitivityMultiplier = getSensitivityMultiplier(options.sensitivityLevel);
    const words = content.toLowerCase().split(/\s+/);
    const detectedWords = [];

    for (const word of words) {
        const cleanWord = word.replace(/[^\w]/g, '');
        if (profanityList.includes(cleanWord)) {
            detectedWords.push(cleanWord);
        }
    }

    const score = detectedWords.length > 0
        ? Math.min(1, (detectedWords.length / words.length) * 10 * sensitivityMultiplier)
        : 0;

    return {
        detected: detectedWords.length > 0,
        score,
        words: detectedWords
    };
}

/**
 * Check content for toxic language
 * @param {string} content - Content to check
 * @param {Object} options - Check options
 * @returns {Object} Toxicity check results
 */
function checkToxicity(content, options) {
    // This is a simplified implementation
    // In a real application, this would use a machine learning model

    const toxicPatterns = [
        { pattern: /\b(hate|hateful)\b/i, type: 'hate', weight: 0.7 },
        { pattern: /\b(threat|threatening|threaten)\b/i, type: 'threat', weight: 0.8 },
        { pattern: /\b(insult|insulting)\b/i, type: 'insult', weight: 0.6 },
        // Add more patterns here
    ];

    const sensitivityMultiplier = getSensitivityMultiplier(options.sensitivityLevel);
    let maxScore = 0;
    let detectedType = null;

    for (const { pattern, type, weight } of toxicPatterns) {
        if (pattern.test(content)) {
            const score = weight * sensitivityMultiplier;
            if (score > maxScore) {
                maxScore = score;
                detectedType = type;
            }
        }
    }

    return {
        detected: maxScore > 0.5,
        score: maxScore,
        type: detectedType
    };
}

/**
 * Check content for sensitive data
 * @param {string} content - Content to check
 * @param {Object} options - Check options
 * @returns {Object} Sensitive data check results
 */
function checkSensitiveData(content, options) {
    // This is a simplified implementation
    // In a real application, this would use more sophisticated pattern matching

    const sensitivePatterns = [
        {
            pattern: /\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b/,
            type: 'SSN',
            weight: 1.0
        },
        {
            // Use a safer pattern with limited repetition
            pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/,
            type: 'Credit Card',
            weight: 0.9
        },
        {
            pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
            type: 'Email',
            weight: 0.6
        },
        // Add more patterns here
    ];

    const sensitivityMultiplier = getSensitivityMultiplier(options.sensitivityLevel);
    let maxScore = 0;
    let detectedType = null;

    for (const { pattern, type, weight } of sensitivePatterns) {
        if (pattern.test(content)) {
            const score = weight * sensitivityMultiplier;
            if (score > maxScore) {
                maxScore = score;
                detectedType = type;
            }
        }
    }

    return {
        detected: maxScore > 0.7,
        score: maxScore,
        type: detectedType
    };
}

/**
 * Check content for spam
 * @param {string} content - Content to check
 * @param {Object} options - Check options
 * @returns {Object} Spam check results
 */
function checkSpam(content, options) {
    // This is a simplified implementation
    // In a real application, this would use more sophisticated techniques

    const sensitivityMultiplier = getSensitivityMultiplier(options.sensitivityLevel);
    let score = 0;

    // Check for repeated characters
    const repeatedCharsRatio = getRepeatedCharsRatio(content);
    if (repeatedCharsRatio > 0.3) {
        score += repeatedCharsRatio * 0.5;
    }

    // Check for all caps
    const allCapsRatio = getAllCapsRatio(content);
    if (allCapsRatio > 0.5) {
        score += allCapsRatio * 0.3;
    }

    // Check for excessive punctuation
    const excessivePunctuationRatio = getExcessivePunctuationRatio(content);
    if (excessivePunctuationRatio > 0.1) {
        score += excessivePunctuationRatio * 0.2;
    }

    // Apply sensitivity multiplier
    score *= sensitivityMultiplier;

    return {
        detected: score > 0.6,
        score: Math.min(1, score)
    };
}

/**
 * Get sensitivity multiplier based on sensitivity level
 * @param {string} level - Sensitivity level
 * @returns {number} Multiplier
 */
function getSensitivityMultiplier(level) {
    switch (level.toLowerCase()) {
        case 'high':
            return 1.5;
        case 'medium':
            return 1.0;
        case 'low':
            return 0.5;
        default:
            return 1.0;
    }
}

/**
 * Get ratio of repeated characters in content
 * @param {string} content - Content to analyze
 * @returns {number} Ratio of repeated characters
 */
function getRepeatedCharsRatio(content) {
    if (!content || content.length < 2) return 0;

    // Use a safer approach with reduce
    const result = content.split('').reduce((acc, char, index, arr) => {
        // Skip the first character since we're comparing with previous
        if (index === 0) return acc;

        // If current char equals previous char, increment count
        if (char === arr[index - 1]) {
            return {
                count: acc.count + 1,
                total: acc.total + 1
            };
        }

        return {
            count: acc.count,
            total: acc.total + 1
        };
    }, { count: 0, total: 0 });

    // Calculate ratio
    return result.count / result.total;
}

/**
 * Get ratio of all caps words in content
 * @param {string} content - Content to analyze
 * @returns {number} Ratio of all caps words
 */
function getAllCapsRatio(content) {
    if (!content) return 0;

    const words = content.split(/\s+/).filter(word => word.length > 2);
    if (words.length === 0) return 0;

    const allCapsWords = words.filter(word => /^[A-Z]+$/.test(word));
    return allCapsWords.length / words.length;
}

/**
 * Get ratio of excessive punctuation in content
 * @param {string} content - Content to analyze
 * @returns {number} Ratio of excessive punctuation
 */
function getExcessivePunctuationRatio(content) {
    if (!content) return 0;

    const punctuationCount = (content.match(/[!?.,;:]/g) || []).length;
    return punctuationCount / content.length;
}

module.exports = { execute };