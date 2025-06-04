/**
 * UX Optimizer - User Experience Enhancement System
 * Provides user-friendly responses, multi-language support, and accessibility features
 */

const crypto = require('crypto');
const logger = require('../logger');

class UXOptimizer {
  constructor() {
    // Response templates for different languages
    this.templates = new Map();
    
    // User preferences cache
    this.userPreferences = new Map();
    
    // Educational content
    this.educationalContent = new Map();
    
    // Feedback tracking
    this.feedbackData = new Map();
    
    // Command shortcuts
    this.shortcuts = new Map();
    
    // Initialize templates and content
    this.initializeTemplates();
    this.initializeEducationalContent();
    this.initializeShortcuts();
  }

  /**
   * Initialize response templates
   */
  initializeTemplates() {
    // English templates
    this.templates.set('en', {
      violation: {
        minimal: '⚠️ Message removed for rule violation.',
        balanced: '⚠️ Your message was removed because it violated our **{category}** policy.',
        detailed: '⚠️ Your message has been removed.\n\n**Reason:** {category}\n**Confidence:** {confidence}%\n**Details:** {reasoning}'
      },
      clean: {
        minimal: '✅ Message approved.',
        balanced: '✅ Your message has been approved and is visible to everyone.',
        detailed: '✅ Your message passed all moderation checks.\n\n**Analysis complete:** No violations detected.'
      },
      warning: {
        minimal: '⚠️ Warning: {reason}',
        balanced: '⚠️ **Warning:** Your message contains content that may violate our {category} policy. Please review our guidelines.',
        detailed: '⚠️ **Warning Issued**\n\n**Category:** {category}\n**Severity:** {severity}\n**Action:** No action taken, but please be mindful of our community guidelines.'
      },
      timeout: {
        minimal: '🔇 You have been timed out for {duration}.',
        balanced: '🔇 You have been temporarily timed out for **{duration}** due to {reason}.',
        detailed: '🔇 **Timeout Applied**\n\n**Duration:** {duration}\n**Reason:** {reason}\n**Expires:** {expiresAt}\n\nYou may appeal this decision by contacting a moderator.'
      },
      error: {
        minimal: '❌ An error occurred.',
        balanced: '❌ Sorry, something went wrong. Please try again.',
        detailed: '❌ **Error:** {error}\n\n**What you can do:**\n{suggestions}'
      }
    });

    // Spanish templates
    this.templates.set('es', {
      violation: {
        minimal: '⚠️ Mensaje eliminado por violación de reglas.',
        balanced: '⚠️ Tu mensaje fue eliminado porque violó nuestra política de **{category}**.',
        detailed: '⚠️ Tu mensaje ha sido eliminado.\n\n**Razón:** {category}\n**Confianza:** {confidence}%\n**Detalles:** {reasoning}'
      },
      clean: {
        minimal: '✅ Mensaje aprobado.',
        balanced: '✅ Tu mensaje ha sido aprobado y es visible para todos.',
        detailed: '✅ Tu mensaje pasó todos los controles de moderación.\n\n**Análisis completo:** No se detectaron violaciones.'
      }
    });

    // French templates
    this.templates.set('fr', {
      violation: {
        minimal: '⚠️ Message supprimé pour violation des règles.',
        balanced: '⚠️ Votre message a été supprimé car il enfreint notre politique de **{category}**.',
        detailed: '⚠️ Votre message a été supprimé.\n\n**Raison:** {category}\n**Confiance:** {confidence}%\n**Détails:** {reasoning}'
      },
      clean: {
        minimal: '✅ Message approuvé.',
        balanced: '✅ Votre message a été approuvé et est visible par tous.',
        detailed: '✅ Votre message a passé tous les contrôles de modération.\n\n**Analyse terminée:** Aucune violation détectée.'
      }
    });

    // German templates
    this.templates.set('de', {
      violation: {
        minimal: '⚠️ Nachricht wegen Regelverletzung entfernt.',
        balanced: '⚠️ Ihre Nachricht wurde entfernt, da sie gegen unsere **{category}**-Richtlinie verstößt.',
        detailed: '⚠️ Ihre Nachricht wurde entfernt.\n\n**Grund:** {category}\n**Vertrauen:** {confidence}%\n**Details:** {reasoning}'
      },
      clean: {
        minimal: '✅ Nachricht genehmigt.',
        balanced: '✅ Ihre Nachricht wurde genehmigt und ist für alle sichtbar.',
        detailed: '✅ Ihre Nachricht hat alle Moderationsprüfungen bestanden.\n\n**Analyse abgeschlossen:** Keine Verstöße festgestellt.'
      }
    });
  }

  /**
   * Initialize educational content
   */
  initializeEducationalContent() {
    this.educationalContent.set('en', {
      'Toxicity': {
        title: '💡 Creating a Positive Community',
        description: 'We all contribute to making this a welcoming space.',
        tips: [
          '• Express disagreements respectfully',
          '• Focus on ideas rather than personal attacks',
          '• Use "I" statements to share your perspective',
          '• Take a break if conversations get heated'
        ],
        resources: [
          { title: '📖 Community Guidelines', command: '/guidelines' },
          { title: '💬 Effective Communication Tips', command: '/communication' }
        ]
      },
      'Harassment': {
        title: '💡 Respecting Others',
        description: 'Everyone deserves to feel safe and respected.',
        tips: [
          '• Respect personal boundaries',
          '• Avoid unwanted contact or attention',
          '• Listen when someone asks you to stop',
          '• Report concerning behavior to moderators'
        ],
        resources: [
          { title: '🛡️ Safety Guidelines', command: '/safety' },
          { title: '📢 How to Report', command: '/report' }
        ]
      },
      'Spam': {
        title: '💡 Keeping Conversations Clean',
        description: 'Quality over quantity makes better discussions.',
        tips: [
          '• Share content that adds value',
          '• Avoid repetitive messages',
          '• Use appropriate channels for promotions',
          '• Check if someone already shared similar content'
        ],
        resources: [
          { title: '📋 Channel Guidelines', command: '/channels' },
          { title: '✅ Posting Best Practices', command: '/posting' }
        ]
      },
      'NSFW': {
        title: '💡 Appropriate Content',
        description: 'Keeping content suitable for all audiences.',
        tips: [
          '• Consider your audience before posting',
          '• Use NSFW channels for mature content',
          '• Add content warnings when needed',
          '• Respect server content policies'
        ],
        resources: [
          { title: '📏 Content Policy', command: '/content-policy' },
          { title: '🔞 NSFW Guidelines', command: '/nsfw-rules' }
        ]
      }
    });
  }

  /**
   * Initialize command shortcuts
   */
  initializeShortcuts() {
    this.shortcuts.set('help', '/modagent_help');
    this.shortcuts.set('?', '/modagent_help');
    this.shortcuts.set('status', '/modagent_status');
    this.shortcuts.set('config', '/modagent_config');
    this.shortcuts.set('stats', '/modagent_stats');
  }

  /**
   * Generate user-friendly response from moderation analysis
   */
  async generateUserResponse(analysis, context) {
    try {
      // Get user preferences
      const preferences = await this.getUserPreferences(context.userId);
      
      // Select template based on violation status
      const responseType = analysis.isViolation ? 'violation' : 'clean';
      const template = this.getTemplate(responseType, preferences.language, preferences.verbosity);
      
      // Fill template with data
      const message = this.fillTemplate(template, {
        category: this.formatCategory(analysis.category, preferences.language),
        confidence: Math.round((analysis.confidence || 0) * 100),
        reasoning: this.simplifyReasoning(analysis.reasoning, preferences.language),
        severity: this.formatSeverity(analysis.severity, preferences.language),
        action: this.formatAction(analysis.recommendedAction, preferences.language)
      });
      
      // Build complete response
      const response = {
        message,
        type: responseType,
        details: preferences.verbosity !== 'minimal' ? this.generateDetails(analysis, preferences) : null,
        educational: analysis.isViolation ? this.getEducationalContent(analysis.category, preferences.language) : null,
        actions: this.generateActions(analysis, preferences),
        accessibility: this.generateAccessibilityInfo(message, preferences),
        feedback: {
          enabled: true,
          requestId: crypto.randomUUID()
        }
      };
      
      return response;
    } catch (error) {
      logger.error('Failed to generate user response:', error);
      return this.generateErrorResponse(error, context);
    }
  }

  /**
   * Get user preferences
   */
  async getUserPreferences(userId) {
    // Check cache
    if (this.userPreferences.has(userId)) {
      return this.userPreferences.get(userId);
    }
    
    // Default preferences
    const defaults = {
      language: 'en',
      verbosity: 'balanced', // minimal, balanced, detailed
      accessibility: {
        screenReader: false,
        highContrast: false,
        reducedMotion: false
      },
      notifications: {
        dm: true,
        channel: true,
        sound: false
      }
    };
    
    // TODO: Load from database
    const preferences = { ...defaults };
    
    // Cache preferences
    this.userPreferences.set(userId, preferences);
    
    return preferences;
  }

  /**
   * Get template based on type and preferences
   */
  getTemplate(type, language = 'en', verbosity = 'balanced') {
    const languageTemplates = this.templates.get(language) || this.templates.get('en');
    const typeTemplates = languageTemplates[type];
    
    if (!typeTemplates) {
      return 'Message processed.';
    }
    
    return typeTemplates[verbosity] || typeTemplates.balanced;
  }

  /**
   * Fill template with values
   */
  fillTemplate(template, values) {
    let result = template;
    
    for (const [key, value] of Object.entries(values)) {
      const placeholder = new RegExp(`\\{${key}\\}`, 'g');
      result = result.replace(placeholder, value || 'N/A');
    }
    
    return result;
  }

  /**
   * Format category for user display
   */
  formatCategory(category, language = 'en') {
    const categoryMap = {
      en: {
        'Toxicity': 'community guidelines',
        'Harassment': 'anti-harassment',
        'Spam': 'anti-spam',
        'NSFW': 'content appropriateness',
        'Other': 'server rules'
      },
      es: {
        'Toxicity': 'normas de la comunidad',
        'Harassment': 'anti-acoso',
        'Spam': 'anti-spam',
        'NSFW': 'contenido apropiado',
        'Other': 'reglas del servidor'
      },
      fr: {
        'Toxicity': 'directives communautaires',
        'Harassment': 'anti-harcèlement',
        'Spam': 'anti-spam',
        'NSFW': 'contenu approprié',
        'Other': 'règles du serveur'
      },
      de: {
        'Toxicity': 'Community-Richtlinien',
        'Harassment': 'Anti-Belästigung',
        'Spam': 'Anti-Spam',
        'NSFW': 'angemessener Inhalt',
        'Other': 'Serverregeln'
      }
    };
    
    const map = categoryMap[language] || categoryMap.en;
    return map[category] || category?.toLowerCase() || 'unknown';
  }

  /**
   * Simplify reasoning for users
   */
  simplifyReasoning(reasoning, language = 'en') {
    if (!reasoning) return '';
    
    // Remove technical jargon
    let simplified = reasoning
      .replace(/\b(confidence score|threshold|algorithm|model)\b/gi, '')
      .replace(/\b\d+(\.\d+)?%?\b/g, '') // Remove percentages
      .trim();
    
    // Translate common phrases
    const translations = {
      en: {
        'detected': 'found',
        'analyzed': 'checked',
        'violation': 'issue',
        'flagged': 'marked'
      },
      es: {
        'detected': 'encontrado',
        'analyzed': 'revisado',
        'violation': 'problema',
        'flagged': 'marcado'
      }
    };
    
    if (translations[language]) {
      for (const [technical, simple] of Object.entries(translations[language])) {
        simplified = simplified.replace(new RegExp(technical, 'gi'), simple);
      }
    }
    
    return simplified;
  }

  /**
   * Format severity level
   */
  formatSeverity(severity, language = 'en') {
    const severityMap = {
      en: {
        'None': 'No issues',
        'Mild': 'Minor',
        'Moderate': 'Moderate',
        'Severe': 'Serious'
      },
      es: {
        'None': 'Sin problemas',
        'Mild': 'Menor',
        'Moderate': 'Moderado',
        'Severe': 'Grave'
      }
    };
    
    const map = severityMap[language] || severityMap.en;
    return map[severity] || severity;
  }

  /**
   * Format action taken
   */
  formatAction(action, language = 'en') {
    const actionMap = {
      en: {
        'none': 'No action taken',
        'flag': 'Flagged for review',
        'warn': 'Warning issued',
        'mute': 'Temporarily muted',
        'kick': 'Removed from server',
        'ban': 'Banned from server',
        'delete': 'Message deleted'
      },
      es: {
        'none': 'Ninguna acción tomada',
        'flag': 'Marcado para revisión',
        'warn': 'Advertencia emitida',
        'mute': 'Silenciado temporalmente',
        'kick': 'Expulsado del servidor',
        'ban': 'Prohibido del servidor',
        'delete': 'Mensaje eliminado'
      }
    };
    
    const map = actionMap[language] || actionMap.en;
    return map[action] || action;
  }

  /**
   * Generate detailed information
   */
  generateDetails(analysis, preferences) {
    const details = {
      category: analysis.category,
      severity: analysis.severity,
      confidence: analysis.confidence,
      action: analysis.recommendedAction
    };
    
    if (preferences.verbosity === 'detailed') {
      details.reasoning = analysis.reasoning;
      details.intent = analysis.intent;
      details.timestamp = new Date().toISOString();
    }
    
    return details;
  }

  /**
   * Get educational content for category
   */
  getEducationalContent(category, language = 'en') {
    const content = this.educationalContent.get(language) || this.educationalContent.get('en');
    return content[category] || null;
  }

  /**
   * Generate available actions
   */
  generateActions(analysis, preferences) {
    const actions = [];
    
    if (analysis.isViolation) {
      actions.push({
        label: 'Appeal Decision',
        command: '/appeal',
        style: 'primary'
      });
      
      actions.push({
        label: 'View Guidelines',
        command: '/guidelines',
        style: 'secondary'
      });
    }
    
    actions.push({
      label: 'Get Help',
      command: '/modagent_help',
      style: 'secondary'
    });
    
    return actions;
  }

  /**
   * Generate accessibility information
   */
  generateAccessibilityInfo(message, preferences) {
    const info = {
      textOnly: message.replace(/[^\w\s.,!?-]/g, ''), // Remove emojis and special chars
      readingTime: Math.ceil(message.split(' ').length / 200), // Minutes at 200 WPM
      language: preferences.language
    };
    
    if (preferences.accessibility.screenReader) {
      info.ariaLabel = this.generateAriaLabel(message);
      info.announcements = this.generateScreenReaderAnnouncements(message);
    }
    
    return info;
  }

  /**
   * Generate ARIA label for screen readers
   */
  generateAriaLabel(message) {
    return message
      .replace(/⚠️/g, 'Warning: ')
      .replace(/✅/g, 'Success: ')
      .replace(/❌/g, 'Error: ')
      .replace(/🔇/g, 'Muted: ')
      .replace(/💡/g, 'Tip: ')
      .replace(/\*\*/g, '') // Remove markdown
      .replace(/\n+/g, '. '); // Convert line breaks to periods
  }

  /**
   * Generate screen reader announcements
   */
  generateScreenReaderAnnouncements(message) {
    const announcements = [];
    
    if (message.includes('⚠️')) {
      announcements.push({
        priority: 'assertive',
        text: 'Moderation action taken'
      });
    }
    
    if (message.includes('✅')) {
      announcements.push({
        priority: 'polite',
        text: 'Message approved'
      });
    }
    
    return announcements;
  }

  /**
   * Generate error response
   */
  generateErrorResponse(error, context) {
    const userFriendlyErrors = {
      'RATE_LIMITED': 'You\'re sending messages too quickly. Please slow down.',
      'NO_PERMISSION': 'You don\'t have permission to do that.',
      'SERVER_ERROR': 'Something went wrong on our end. Please try again.',
      'INVALID_INPUT': 'Your message couldn\'t be processed. Please check and try again.'
    };
    
    const message = userFriendlyErrors[error.code] || 'An unexpected error occurred.';
    
    return {
      message: `❌ ${message}`,
      type: 'error',
      details: {
        code: error.code,
        requestId: context.requestId || crypto.randomUUID()
      },
      actions: [
        {
          label: 'Get Help',
          command: '/support',
          style: 'primary'
        },
        {
          label: 'Report Issue',
          command: '/report_issue',
          style: 'secondary'
        }
      ]
    };
  }

  /**
   * Format command with auto-completion
   */
  formatCommand(command, options = {}) {
    const formatted = {
      name: command,
      description: this.getCommandDescription(command),
      usage: this.getCommandUsage(command),
      examples: this.getCommandExamples(command),
      aliases: this.getCommandAliases(command)
    };
    
    if (options.suggest) {
      formatted.suggestions = this.getCommandSuggestions(command, options.context);
    }
    
    return formatted;
  }

  /**
   * Get command description
   */
  getCommandDescription(command) {
    const descriptions = {
      '/modagent_help': 'Get help with moderation commands',
      '/modagent_status': 'Check current moderation status',
      '/modagent_config': 'Configure moderation settings',
      '/modagent_stats': 'View moderation statistics',
      '/appeal': 'Appeal a moderation decision',
      '/guidelines': 'View community guidelines'
    };
    
    return descriptions[command] || 'No description available';
  }

  /**
   * Get command usage
   */
  getCommandUsage(command) {
    const usage = {
      '/modagent_stats': '/modagent_stats [timeframe]',
      '/modagent_review': '/modagent_review <message_id>',
      '/modagent_exempt': '/modagent_exempt <@user> [duration]'
    };
    
    return usage[command] || command;
  }

  /**
   * Get command examples
   */
  getCommandExamples(command) {
    const examples = {
      '/modagent_stats': [
        '/modagent_stats today',
        '/modagent_stats week',
        '/modagent_stats month'
      ],
      '/modagent_exempt': [
        '/modagent_exempt @user 60',
        '/modagent_exempt @user'
      ]
    };
    
    return examples[command] || [];
  }

  /**
   * Get command aliases
   */
  getCommandAliases(command) {
    const aliases = {
      '/modagent_help': ['/help', '/?'],
      '/modagent_status': ['/status'],
      '/modagent_config': ['/config'],
      '/modagent_stats': ['/stats']
    };
    
    return aliases[command] || [];
  }

  /**
   * Get command suggestions based on context
   */
  getCommandSuggestions(command, context) {
    const suggestions = [];
    
    if (command === '/modagent_stats') {
      suggestions.push(
        { value: 'today', description: 'Statistics for today' },
        { value: 'week', description: 'Statistics for this week' },
        { value: 'month', description: 'Statistics for this month' }
      );
    }
    
    return suggestions;
  }

  /**
   * Collect user feedback
   */
  async collectFeedback(userId, requestId, feedback) {
    try {
      const feedbackEntry = {
        userId,
        requestId,
        helpful: feedback.helpful,
        rating: feedback.rating,
        comment: feedback.comment,
        timestamp: Date.now()
      };
      
      // Store feedback
      this.feedbackData.set(requestId, feedbackEntry);
      
      // Analyze feedback patterns
      await this.analyzeFeedback(userId);
      
      return {
        success: true,
        message: 'Thank you for your feedback!'
      };
    } catch (error) {
      logger.error('Failed to collect feedback:', error);
      return {
        success: false,
        message: 'Failed to save feedback'
      };
    }
  }

  /**
   * Analyze user feedback patterns
   */
  async analyzeFeedback(userId) {
    const userFeedback = Array.from(this.feedbackData.values())
      .filter(f => f.userId === userId);
    
    if (userFeedback.length < 5) return;
    
    const stats = {
      total: userFeedback.length,
      helpful: userFeedback.filter(f => f.helpful).length,
      avgRating: userFeedback.reduce((sum, f) => sum + (f.rating || 0), 0) / userFeedback.length
    };
    
    // Adjust preferences based on feedback
    if (stats.helpful / stats.total < 0.5) {
      await this.suggestPreferenceChange(userId, 'verbosity', 'detailed');
    }
    
    if (stats.avgRating < 3) {
      await this.suggestPreferenceChange(userId, 'notifications', { dm: true });
    }
  }

  /**
   * Suggest preference changes
   */
  async suggestPreferenceChange(userId, preference, value) {
    // This would notify the user about suggested changes
    logger.info('Suggesting preference change', {
      userId,
      preference,
      value
    });
  }

  /**
   * Generate onboarding flow for new users
   */
  async generateOnboarding(userId, serverId) {
    const steps = [
      {
        title: 'Welcome to AI Moderation! 👋',
        description: 'I\'m here to help keep this community safe and welcoming.',
        action: {
          label: 'Get Started',
          command: '/modagent_help'
        }
      },
      {
        title: 'Customize Your Experience 🎨',
        description: 'Set your language and notification preferences.',
        action: {
          label: 'Set Preferences',
          command: '/preferences'
        }
      },
      {
        title: 'Review Community Guidelines 📋',
        description: 'Understanding the rules helps everyone have a great time.',
        action: {
          label: 'View Guidelines',
          command: '/guidelines'
        }
      },
      {
        title: 'You\'re All Set! 🎉',
        description: 'If you have questions, just ask for help anytime.',
        action: {
          label: 'Finish Setup',
          command: '/finish_onboarding'
        }
      }
    ];
    
    return {
      userId,
      serverId,
      steps,
      currentStep: 0,
      completed: false
    };
  }
}

// Export singleton instance
module.exports = new UXOptimizer();