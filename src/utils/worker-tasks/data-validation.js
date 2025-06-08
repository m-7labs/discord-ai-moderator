/**
 * Data Validation Worker Task
 * Performs CPU-intensive data validation against schemas
 */

/**
 * Execute the data validation task
 * @param {Object} data - Task input data
 * @param {Object} data.data - Data to validate
 * @param {Object} data.schema - Validation schema
 * @param {Object} context - Execution context
 * @returns {Object} Validation results
 */
async function execute(data = {}, context = {}) {
    try {
        // Validate input
        if (!data || !data.data) {
            throw new Error('Data is required for validation');
        }

        if (!data.schema) {
            throw new Error('Schema is required for validation');
        }

        const inputData = data.data;
        const schema = data.schema;

        // Start timing the validation
        const startTime = process.hrtime.bigint();

        // Validate the data
        const results = validateData(inputData, schema);

        // Calculate processing time
        const endTime = process.hrtime.bigint();
        const processingTime = Number(endTime - startTime) / 1_000_000; // Convert to ms

        // Return results with metadata
        return {
            results,
            meta: {
                processingTime,
                schemaId: schema.id || 'unknown',
                workerId: context.workerId || 'unknown'
            }
        };
    } catch (error) {
        console.error('Error in data validation task:', error);
        throw new Error(`Data validation failed: ${error.message}`);
    }
}

/**
 * Validate data against a schema
 * @param {Object} data - Data to validate
 * @param {Object} schema - Validation schema
 * @returns {Object} Validation results
 */
function validateData(data, schema) {
    // Initialize results
    const results = {
        valid: true,
        errors: [],
        warnings: [],
        validatedFields: 0,
        totalFields: 0
    };

    // Validate data structure
    if (typeof data !== 'object' || data === null) {
        results.valid = false;
        results.errors.push({
            path: '',
            message: `Expected an object, got ${typeof data}`
        });
        return results;
    }

    // Validate schema structure
    if (typeof schema !== 'object' || schema === null || !schema.fields) {
        results.valid = false;
        results.errors.push({
            path: '',
            message: 'Invalid schema format'
        });
        return results;
    }

    // Count total fields
    results.totalFields = Object.keys(schema.fields).length;

    // Validate each field
    for (const [fieldName, fieldSchema] of Object.entries(schema.fields)) {
        try {
            const fieldResult = validateField(
                getNestedValue(data, fieldName),
                fieldSchema,
                fieldName
            );

            // Add field validation results
            if (fieldResult.valid) {
                results.validatedFields++;
            } else {
                results.errors.push(...fieldResult.errors);
                results.warnings.push(...fieldResult.warnings);
            }
        } catch (error) {
            results.errors.push({
                path: fieldName,
                message: `Validation error: ${error.message}`
            });
        }
    }

    // Check for required fields
    if (schema.required && Array.isArray(schema.required)) {
        for (const requiredField of schema.required) {
            if (getNestedValue(data, requiredField) === undefined) {
                results.errors.push({
                    path: requiredField,
                    message: 'Required field is missing'
                });
            }
        }
    }

    // Check for unknown fields if strictMode is enabled
    if (schema.strictMode === true) {
        const schemaFields = new Set(Object.keys(schema.fields));
        const dataFields = getAllFieldPaths(data);

        for (const field of dataFields) {
            if (!schemaFields.has(field)) {
                results.warnings.push({
                    path: field,
                    message: 'Unknown field not defined in schema'
                });
            }
        }
    }

    // Update valid flag based on errors
    results.valid = results.errors.length === 0;

    return results;
}

/**
 * Validate a single field against its schema
 * @param {any} value - Field value
 * @param {Object} fieldSchema - Field schema
 * @param {string} path - Field path
 * @returns {Object} Field validation results
 */
function validateField(value, fieldSchema, path) {
    const result = {
        valid: true,
        errors: [],
        warnings: []
    };

    // Handle undefined value
    if (value === undefined) {
        if (fieldSchema.required) {
            result.valid = false;
            result.errors.push({
                path,
                message: 'Required field is missing'
            });
        }
        return result;
    }

    // Type validation
    if (fieldSchema.type) {
        const typeValid = validateType(value, fieldSchema.type);
        if (!typeValid) {
            result.valid = false;
            result.errors.push({
                path,
                message: `Expected type ${fieldSchema.type}, got ${typeof value}`
            });
            return result; // Stop validation if type is wrong
        }
    }

    // String validations
    if (fieldSchema.type === 'string') {
        // Min length
        if (fieldSchema.minLength !== undefined && value.length < fieldSchema.minLength) {
            result.valid = false;
            result.errors.push({
                path,
                message: `String length ${value.length} is less than minimum ${fieldSchema.minLength}`
            });
        }

        // Max length
        if (fieldSchema.maxLength !== undefined && value.length > fieldSchema.maxLength) {
            result.valid = false;
            result.errors.push({
                path,
                message: `String length ${value.length} exceeds maximum ${fieldSchema.maxLength}`
            });
        }

        // Pattern - only use predefined patterns for security
        if (fieldSchema.pattern) {
            try {
                // Use a pattern validator that only accepts known safe patterns
                const isValid = validatePattern(value, fieldSchema.pattern);
                if (!isValid) {
                    result.valid = false;
                    result.errors.push({
                        path,
                        message: `String does not match pattern ${fieldSchema.pattern}`
                    });
                }
            } catch (error) {
                result.warnings.push({
                    path,
                    message: `Invalid pattern in schema: ${error.message}`
                });
            }
        }

        // Enum
        if (fieldSchema.enum && Array.isArray(fieldSchema.enum)) {
            if (!fieldSchema.enum.includes(value)) {
                result.valid = false;
                result.errors.push({
                    path,
                    message: `Value must be one of: ${fieldSchema.enum.join(', ')}`
                });
            }
        }
    }

    // Number validations
    if (fieldSchema.type === 'number' || fieldSchema.type === 'integer') {
        // Minimum
        if (fieldSchema.minimum !== undefined && value < fieldSchema.minimum) {
            result.valid = false;
            result.errors.push({
                path,
                message: `Value ${value} is less than minimum ${fieldSchema.minimum}`
            });
        }

        // Maximum
        if (fieldSchema.maximum !== undefined && value > fieldSchema.maximum) {
            result.valid = false;
            result.errors.push({
                path,
                message: `Value ${value} exceeds maximum ${fieldSchema.maximum}`
            });
        }

        // Integer check
        if (fieldSchema.type === 'integer' && !Number.isInteger(value)) {
            result.valid = false;
            result.errors.push({
                path,
                message: `Value must be an integer`
            });
        }

        // Multiple of
        if (fieldSchema.multipleOf !== undefined) {
            if (value % fieldSchema.multipleOf !== 0) {
                result.valid = false;
                result.errors.push({
                    path,
                    message: `Value must be a multiple of ${fieldSchema.multipleOf}`
                });
            }
        }
    }

    // Array validations
    if (fieldSchema.type === 'array') {
        // Min items
        if (fieldSchema.minItems !== undefined && value.length < fieldSchema.minItems) {
            result.valid = false;
            result.errors.push({
                path,
                message: `Array length ${value.length} is less than minimum ${fieldSchema.minItems}`
            });
        }

        // Max items
        if (fieldSchema.maxItems !== undefined && value.length > fieldSchema.maxItems) {
            result.valid = false;
            result.errors.push({
                path,
                message: `Array length ${value.length} exceeds maximum ${fieldSchema.maxItems}`
            });
        }

        // Items validation
        if (fieldSchema.items && value.length > 0) {
            // Use forEach with index for safer iteration
            value.forEach((item, i) => {
                const itemResult = validateField(
                    item,
                    fieldSchema.items,
                    `${path}[${i}]`
                );

                if (!itemResult.valid) {
                    result.valid = false;
                    result.errors.push(...itemResult.errors);
                    result.warnings.push(...itemResult.warnings);
                }
            });
        }

        // Unique items
        if (fieldSchema.uniqueItems === true) {
            const uniqueValues = new Set();
            const duplicates = [];

            // Use forEach with index for safer iteration
            value.forEach((item, i) => {
                const itemStr = JSON.stringify(item);

                if (uniqueValues.has(itemStr)) {
                    duplicates.push(i);
                } else {
                    uniqueValues.add(itemStr);
                }
            });

            if (duplicates.length > 0) {
                result.valid = false;
                result.errors.push({
                    path,
                    message: `Array must have unique items. Duplicates at indices: ${duplicates.join(', ')}`
                });
            }
        }
    }

    // Object validations
    if (fieldSchema.type === 'object' && fieldSchema.properties) {
        // Validate nested properties
        Object.entries(fieldSchema.properties).forEach(([propName, propSchema]) => {
            const propPath = path ? `${path}.${propName}` : propName;
            // Use safer property access
            const propValue = Object.prototype.hasOwnProperty.call(value, propName)
                ? Object.getOwnPropertyDescriptor(value, propName).value
                : undefined;

            const propResult = validateField(propValue, propSchema, propPath);

            if (!propResult.valid) {
                result.valid = false;
                result.errors.push(...propResult.errors);
                result.warnings.push(...propResult.warnings);
            }
        });

        // Required properties
        if (fieldSchema.required && Array.isArray(fieldSchema.required)) {
            fieldSchema.required.forEach(requiredProp => {
                // Use safer property check
                if (!Object.prototype.hasOwnProperty.call(value, requiredProp)) {
                    result.valid = false;
                    result.errors.push({
                        path: path ? `${path}.${requiredProp}` : requiredProp,
                        message: 'Required property is missing'
                    });
                }
            });
        }
    }

    // Custom validation function
    if (fieldSchema.validate && typeof fieldSchema.validate === 'function') {
        try {
            const customResult = fieldSchema.validate(value);

            if (customResult !== true) {
                result.valid = false;
                result.errors.push({
                    path,
                    message: customResult || 'Failed custom validation'
                });
            }
        } catch (error) {
            result.valid = false;
            result.errors.push({
                path,
                message: `Custom validation error: ${error.message}`
            });
        }
    }

    return result;
}

/**
 * Validate value against type
 * @param {any} value - Value to validate
 * @param {string} type - Expected type
 * @returns {boolean} Whether the value matches the type
 */
function validateType(value, type) {
    switch (type) {
        case 'string':
            return typeof value === 'string';
        case 'number':
            return typeof value === 'number' && !isNaN(value);
        case 'integer':
            return typeof value === 'number' && !isNaN(value) && Number.isInteger(value);
        case 'boolean':
            return typeof value === 'boolean';
        case 'array':
            return Array.isArray(value);
        case 'object':
            return typeof value === 'object' && value !== null && !Array.isArray(value);
        case 'null':
            return value === null;
        case 'any':
            return true;
        default:
            return false;
    }
}

/**
 * Validate a string against a predefined pattern
 * @param {string} value - String to validate
 * @param {string} patternName - Name of the pattern
 * @returns {boolean} Whether the string matches the pattern
 */
function validatePattern(value, patternName) {
    // Use pattern-specific validation functions instead of regex
    switch (patternName) {
        case 'email':
            return validateEmail(value);
        case 'url':
            return validateUrl(value);
        case 'date':
            return validateDate(value);
        case 'time':
            return validateTime(value);
        case 'datetime':
            return validateDateTime(value);
        case 'uuid':
            return validateUuid(value);
        case 'alpha':
            return validateAlpha(value);
        case 'alphanumeric':
            return validateAlphanumeric(value);
        case 'numeric':
            return validateNumeric(value);
        case 'integer':
            return validateInteger(value);
        case 'decimal':
            return validateDecimal(value);
        case 'color':
            return validateColor(value);
        case 'ipv4':
            return validateIpv4(value);
        case 'phone':
            return validatePhone(value);
        default:
            throw new Error(`Unknown pattern: ${patternName}`);
    }
}

// Pattern validation helper functions
function validateEmail(value) {
    if (typeof value !== 'string') return false;

    // Basic email validation
    const parts = value.split('@');
    if (parts.length !== 2) return false;

    const [local, domain] = parts;
    if (!local || !domain) return false;

    const domainParts = domain.split('.');
    if (domainParts.length < 2) return false;

    return true;
}

function validateUrl(value) {
    if (typeof value !== 'string') return false;

    // Basic URL validation
    try {
        const url = new URL(value);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch {
        return false;
    }
}

function validateDate(value) {
    if (typeof value !== 'string') return false;

    // YYYY-MM-DD format
    const parts = value.split('-');
    if (parts.length !== 3) return false;

    const year = parseInt(parts[0], 10);
    const month = parseInt(parts[1], 10);
    const day = parseInt(parts[2], 10);

    return !isNaN(year) && !isNaN(month) && !isNaN(day) &&
        year >= 1000 && year <= 9999 &&
        month >= 1 && month <= 12 &&
        day >= 1 && day <= 31;
}

function validateTime(value) {
    if (typeof value !== 'string') return false;

    // HH:MM or HH:MM:SS format
    const parts = value.split(':');
    if (parts.length < 2 || parts.length > 3) return false;

    const hours = parseInt(parts[0], 10);
    const minutes = parseInt(parts[1], 10);
    const seconds = parts.length === 3 ? parseInt(parts[2], 10) : 0;

    return !isNaN(hours) && !isNaN(minutes) && !isNaN(seconds) &&
        hours >= 0 && hours <= 23 &&
        minutes >= 0 && minutes <= 59 &&
        seconds >= 0 && seconds <= 59;
}

function validateDateTime(value) {
    if (typeof value !== 'string') return false;

    // Basic ISO datetime validation
    const parts = value.split('T');
    if (parts.length !== 2) return false;

    return validateDate(parts[0]) && validateTime(parts[1].split(/[Z+-]/)[0]);
}

function validateUuid(value) {
    if (typeof value !== 'string') return false;

    // Basic UUID validation
    const parts = value.split('-');
    if (parts.length !== 5) return false;

    return parts[0].length === 8 &&
        parts[1].length === 4 &&
        parts[2].length === 4 &&
        parts[3].length === 4 &&
        parts[4].length === 12;
}

function validateAlpha(value) {
    if (typeof value !== 'string') return false;

    for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (!((code >= 65 && code <= 90) || (code >= 97 && code <= 122))) {
            return false;
        }
    }

    return value.length > 0;
}

function validateAlphanumeric(value) {
    if (typeof value !== 'string') return false;

    for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (!((code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122))) {
            return false;
        }
    }

    return value.length > 0;
}

function validateNumeric(value) {
    if (typeof value !== 'string') return false;

    for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (!(code >= 48 && code <= 57)) {
            return false;
        }
    }

    return value.length > 0;
}

function validateInteger(value) {
    if (typeof value !== 'string') return false;

    if (value.length === 0) return false;

    let startIndex = 0;
    if (value[0] === '-' || value[0] === '+') {
        startIndex = 1;
        if (value.length === 1) return false;
    }

    for (let i = startIndex; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (!(code >= 48 && code <= 57)) {
            return false;
        }
    }

    return true;
}

function validateDecimal(value) {
    if (typeof value !== 'string') return false;

    return !isNaN(parseFloat(value)) && isFinite(value);
}

function validateColor(value) {
    if (typeof value !== 'string') return false;

    // #RGB or #RRGGBB format
    if (value[0] !== '#') return false;

    if (value.length !== 4 && value.length !== 7) return false;

    for (let i = 1; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (!((code >= 48 && code <= 57) || (code >= 65 && code <= 70) || (code >= 97 && code <= 102))) {
            return false;
        }
    }

    return true;
}

function validateIpv4(value) {
    if (typeof value !== 'string') return false;

    const parts = value.split('.');
    if (parts.length !== 4) return false;

    for (const part of parts) {
        const num = parseInt(part, 10);
        if (isNaN(num) || num < 0 || num > 255 || part !== num.toString()) {
            return false;
        }
    }

    return true;
}

function validatePhone(value) {
    if (typeof value !== 'string') return false;

    // Basic phone validation
    let digits = 0;

    // Use split and forEach to avoid direct character access
    value.split('').forEach(char => {
        // Check if char is a digit
        if (char >= '0' && char <= '9') {
            digits++;
        }
        // Check if char is a valid phone number symbol
        else if (!['+', '-', ' ', '(', ')'].includes(char)) {
            digits = -1; // Mark as invalid
        }
    });

    return digits >= 7 && digits <= 15;
}

/**
 * Get a nested value from an object using a dot-notation path
 * @param {Object} obj - Object to get value from
 * @param {string} path - Dot-notation path
 * @returns {any} The value at the path
 */
function getNestedValue(obj, path) {
    if (!obj || !path) return undefined;

    const parts = path.split('.');
    let current = obj;

    for (const part of parts) {
        if (current === undefined || current === null) return undefined;

        // Handle array indices in path (e.g., "items[0].name")
        // Use string operations instead of regex
        const bracketIndex = part.indexOf('[');
        if (bracketIndex > 0 && part.endsWith(']')) {
            const key = part.substring(0, bracketIndex);
            const indexStr = part.substring(bracketIndex + 1, part.length - 1);

            // Use safer property access
            if (!Object.prototype.hasOwnProperty.call(current, key)) {
                return undefined;
            }

            current = Object.getOwnPropertyDescriptor(current, key).value;

            if (indexStr && Array.isArray(current)) {
                const idx = parseInt(indexStr, 10);
                if (!isNaN(idx) && idx >= 0 && idx < current.length) {
                    // Use array access with bounds checking
                    current = Array.prototype.at.call(current, idx);
                } else {
                    return undefined;
                }
            }
        } else {
            // Use safer property access
            if (!Object.prototype.hasOwnProperty.call(current, part)) {
                return undefined;
            }

            current = Object.getOwnPropertyDescriptor(current, part).value;
        }
    }

    return current;
}

/**
 * Get all field paths in an object
 * @param {Object} obj - Object to get paths from
 * @param {string} prefix - Path prefix
 * @returns {Set<string>} Set of all field paths
 */
function getAllFieldPaths(obj, prefix = '') {
    const paths = new Set();

    if (typeof obj !== 'object' || obj === null) {
        return paths;
    }

    // Use Object.entries for safer iteration
    Object.entries(obj).forEach(([key, value]) => {
        const path = prefix ? `${prefix}.${key}` : key;
        paths.add(path);

        if (typeof value === 'object' && value !== null) {
            const nestedPaths = getAllFieldPaths(value, path);
            nestedPaths.forEach(nestedPath => {
                paths.add(nestedPath);
            });
        }
    });

    return paths;
}

module.exports = { execute };