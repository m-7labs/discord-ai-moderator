/**
 * Text Processing Worker Task
 * Performs CPU-intensive text processing operations
 */

/**
 * Execute the text processing task
 * @param {Object} data - Task input data
 * @param {string} data.text - Text to process
 * @param {Object} data.options - Processing options
 * @param {Object} context - Execution context
 * @returns {Object} Processing results
 */
async function execute(data = {}, context = {}) {
    try {
        // Validate input
        if (!data || !data.text) {
            throw new Error('Text is required for processing');
        }

        const text = data.text;
        const options = data.options || {};

        // Default options
        const processingOptions = {
            tokenize: options.tokenize !== false,
            extractEntities: options.extractEntities !== false,
            calculateStats: options.calculateStats !== false,
            summarize: options.summarize === true,
            maxSummaryLength: options.maxSummaryLength || 100,
            language: options.language || 'en',
            ...options
        };

        // Start timing the processing
        const startTime = process.hrtime.bigint();

        // Process the text
        const results = await processText(text, processingOptions);

        // Calculate processing time
        const endTime = process.hrtime.bigint();
        const processingTime = Number(endTime - startTime) / 1_000_000; // Convert to ms

        // Return results with metadata
        return {
            results,
            meta: {
                processingTime,
                textLength: text.length,
                options: processingOptions,
                workerId: context.workerId || 'unknown'
            }
        };
    } catch (error) {
        console.error('Error in text processing task:', error);
        throw new Error(`Text processing failed: ${error.message}`);
    }
}

/**
 * Process text with various operations
 * @param {string} text - Text to process
 * @param {Object} options - Processing options
 * @returns {Promise<Object>} Processing results
 */
async function processText(text, options) {
    // Initialize results object
    const results = {
        originalText: text,
        processedText: text,
        stats: {},
        tokens: [],
        entities: [],
        summary: ''
    };

    // Tokenize text if enabled
    if (options.tokenize) {
        results.tokens = tokenizeText(text, options.language);
    }

    // Extract entities if enabled
    if (options.extractEntities) {
        results.entities = extractEntities(text, options.language);
    }

    // Calculate statistics if enabled
    if (options.calculateStats) {
        results.stats = calculateTextStats(text);
    }

    // Generate summary if enabled
    if (options.summarize) {
        results.summary = summarizeText(text, options.maxSummaryLength);
    }

    // Apply any text transformations
    if (options.transformations && Array.isArray(options.transformations)) {
        results.processedText = applyTransformations(text, options.transformations);
    }

    return results;
}

/**
 * Tokenize text into words and sentences
 * @param {string} text - Text to tokenize
 * @param {string} language - Language code
 * @returns {Object} Tokenization results
 */
function tokenizeText(text, _language) {
    // Simple tokenization implementation
    // In a real application, this would use a more sophisticated NLP library

    // Split into sentences (simple approach)
    const sentenceDelimiters = /[.!?]+/;
    const sentences = text
        .split(sentenceDelimiters)
        .map(s => s.trim())
        .filter(s => s.length > 0);

    // Split into words (simple approach)
    const wordDelimiters = /\s+/;
    const words = text
        .split(wordDelimiters)
        .map(w => w.trim().toLowerCase())
        .filter(w => w.length > 0);

    // Count word frequencies
    const wordFrequency = {};
    for (const word of words) {
        // Use a safer approach to increment counts
        const currentCount = Object.prototype.hasOwnProperty.call(wordFrequency, word)
            ? Object.getOwnPropertyDescriptor(wordFrequency, word).value
            : 0;

        // Create a new property with defineProperty
        Object.defineProperty(wordFrequency, word, {
            value: currentCount + 1,
            enumerable: true,
            configurable: true,
            writable: true
        });
    }

    return {
        sentences: sentences,
        words: words,
        wordCount: words.length,
        sentenceCount: sentences.length,
        wordFrequency: wordFrequency
    };
}

/**
 * Extract entities from text
 * @param {string} text - Text to analyze
 * @param {string} language - Language code
 * @returns {Array} Extracted entities
 */
function extractEntities(text, _language) {
    // Simple entity extraction implementation
    // In a real application, this would use a more sophisticated NLP library

    const entities = [];

    // Extract emails
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
    const emails = text.match(emailRegex) || [];

    for (const email of emails) {
        entities.push({
            type: 'email',
            value: email,
            position: text.indexOf(email)
        });
    }

    // Extract URLs
    const urlRegex = /https?:\/\/[^\s]+/g;
    const urls = text.match(urlRegex) || [];

    for (const url of urls) {
        entities.push({
            type: 'url',
            value: url,
            position: text.indexOf(url)
        });
    }

    // Extract dates (simple approach)
    const dateRegex = /\b\d{1,2}[/\-.]?\d{1,2}[/\-.]?\d{2,4}\b/g;
    const dates = text.match(dateRegex) || [];

    for (const date of dates) {
        entities.push({
            type: 'date',
            value: date,
            position: text.indexOf(date)
        });
    }

    return entities;
}

/**
 * Calculate text statistics
 * @param {string} text - Text to analyze
 * @returns {Object} Text statistics
 */
function calculateTextStats(text) {
    if (!text) return {};

    // Calculate basic statistics
    const charCount = text.length;
    const wordCount = text.split(/\s+/).filter(w => w.length > 0).length;
    const sentenceCount = text.split(/[.!?]+/).filter(s => s.trim().length > 0).length;
    const paragraphCount = text.split(/\n\s*\n/).filter(p => p.trim().length > 0).length;

    // Calculate average word length
    const words = text.split(/\s+/).filter(w => w.length > 0);
    const totalWordLength = words.reduce((sum, word) => sum + word.length, 0);
    const avgWordLength = wordCount > 0 ? totalWordLength / wordCount : 0;

    // Calculate average sentence length
    const avgWordsPerSentence = sentenceCount > 0 ? wordCount / sentenceCount : 0;

    // Calculate readability (simplified Flesch-Kincaid)
    const syllableCount = estimateSyllables(text);
    const readabilityScore = calculateReadabilityScore(wordCount, sentenceCount, syllableCount);

    return {
        charCount,
        wordCount,
        sentenceCount,
        paragraphCount,
        avgWordLength: avgWordLength.toFixed(2),
        avgWordsPerSentence: avgWordsPerSentence.toFixed(2),
        readabilityScore: readabilityScore.toFixed(2),
        estimatedReadingTime: calculateReadingTime(wordCount)
    };
}

/**
 * Estimate syllable count in text
 * @param {string} text - Text to analyze
 * @returns {number} Estimated syllable count
 */
function estimateSyllables(text) {
    // Simple syllable estimation
    // In a real application, this would use a more sophisticated algorithm

    const words = text.split(/\s+/).filter(w => w.length > 0);
    let syllableCount = 0;

    for (const word of words) {
        // Count vowel groups as syllables
        const vowelGroups = word.toLowerCase().match(/[aeiouy]+/g) || [];
        let wordSyllables = vowelGroups.length;

        // Adjust for common patterns
        if (word.match(/[aeiouy]$/)) {
            // Words ending in vowels often have clear syllable
        } else if (word.match(/e$/)) {
            // Silent e at the end
            wordSyllables = Math.max(1, wordSyllables - 1);
        }

        // Every word has at least one syllable
        syllableCount += Math.max(1, wordSyllables);
    }

    return syllableCount;
}

/**
 * Calculate readability score
 * @param {number} wordCount - Number of words
 * @param {number} sentenceCount - Number of sentences
 * @param {number} syllableCount - Number of syllables
 * @returns {number} Readability score
 */
function calculateReadabilityScore(wordCount, sentenceCount, syllableCount) {
    if (wordCount === 0 || sentenceCount === 0) return 0;

    // Simplified Flesch-Kincaid Grade Level
    const score = 0.39 * (wordCount / sentenceCount) + 11.8 * (syllableCount / wordCount) - 15.59;

    // Clamp score to reasonable range
    return Math.max(0, Math.min(18, score));
}

/**
 * Calculate estimated reading time
 * @param {number} wordCount - Number of words
 * @returns {string} Estimated reading time
 */
function calculateReadingTime(wordCount) {
    // Average reading speed: 200-250 words per minute
    const wordsPerMinute = 225;
    const minutes = wordCount / wordsPerMinute;

    if (minutes < 1) {
        const seconds = Math.round(minutes * 60);
        return `${seconds} second${seconds !== 1 ? 's' : ''}`;
    } else if (minutes < 60) {
        const roundedMinutes = Math.round(minutes);
        return `${roundedMinutes} minute${roundedMinutes !== 1 ? 's' : ''}`;
    } else {
        const hours = Math.floor(minutes / 60);
        const remainingMinutes = Math.round(minutes % 60);
        return `${hours} hour${hours !== 1 ? 's' : ''} ${remainingMinutes} minute${remainingMinutes !== 1 ? 's' : ''}`;
    }
}

/**
 * Summarize text
 * @param {string} text - Text to summarize
 * @param {number} maxLength - Maximum summary length
 * @returns {string} Summarized text
 */
function summarizeText(text, maxLength) {
    // Simple extractive summarization
    // In a real application, this would use a more sophisticated algorithm

    // Split into sentences
    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);

    if (sentences.length <= 3) {
        // Text is already short, return as is
        return text;
    }

    // Score sentences based on position and length
    const scoredSentences = sentences.map((sentence, index) => {
        // Position score - first and last sentences are important
        const positionScore = (index === 0 || index === sentences.length - 1) ? 2 : 1;

        // Length score - prefer medium-length sentences
        const words = sentence.split(/\s+/).filter(w => w.length > 0);
        const lengthScore = words.length > 5 && words.length < 25 ? 1.5 : 1;

        return {
            text: sentence.trim(),
            score: positionScore * lengthScore,
            index
        };
    });

    // Sort by score (descending)
    scoredSentences.sort((a, b) => b.score - a.score);

    // Take top sentences (about 30% of original)
    const numSentences = Math.max(1, Math.min(3, Math.ceil(sentences.length * 0.3)));
    const topSentences = scoredSentences.slice(0, numSentences);

    // Sort by original position
    topSentences.sort((a, b) => a.index - b.index);

    // Join sentences
    let summary = topSentences.map(s => s.text).join('. ');

    // Add period if needed
    if (!summary.endsWith('.') && !summary.endsWith('!') && !summary.endsWith('?')) {
        summary += '.';
    }

    // Truncate if too long
    if (summary.length > maxLength) {
        summary = summary.substring(0, maxLength - 3) + '...';
    }

    return summary;
}

/**
 * Apply text transformations
 * @param {string} text - Text to transform
 * @param {Array} transformations - List of transformations to apply
 * @returns {string} Transformed text
 */
function applyTransformations(text, transformations) {
    let result = text;

    for (const transformation of transformations) {
        switch (transformation) {
            case 'uppercase':
                result = result.toUpperCase();
                break;
            case 'lowercase':
                result = result.toLowerCase();
                break;
            case 'capitalize':
                result = result.replace(/\b\w/g, c => c.toUpperCase());
                break;
            case 'trim':
                result = result.trim();
                break;
            case 'remove_extra_spaces':
                result = result.replace(/\s+/g, ' ');
                break;
            case 'remove_punctuation':
                result = result.replace(/[^\w\s]/g, '');
                break;
            default:
                // Unknown transformation, ignore
                break;
        }
    }

    return result;
}

module.exports = { execute };