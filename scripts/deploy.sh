#!/bin/bash

# Discord AI Moderator Deployment Script
# This script helps you quickly deploy the bot

echo "🤖 Discord AI Moderator - Quick Deploy Script"
echo "=============================================="

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18 or higher."
    echo "   Download from: https://nodejs.org"
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'.' -f1 | cut -d'v' -f2)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "❌ Node.js version 18 or higher is required. You have version $(node -v)"
    echo "   Please upgrade from: https://nodejs.org"
    exit 1
fi

echo "✅ Node.js $(node -v) detected"

# Check if npm is available
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not available. Please install npm."
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
npm install

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo "✅ Dependencies installed successfully"

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "⚙️ Creating environment file..."
    cp .env.example .env
    
    echo ""
    echo "🔧 IMPORTANT: You need to edit the .env file with your configuration:"
    echo "   - DISCORD_BOT_TOKEN (from Discord Developer Portal)"
    echo "   - CLIENT_ID (your Discord application ID)"
    echo "   - ANTHROPIC_API_KEY (from Anthropic Console)"
    echo "   - MONGODB_URI (your MongoDB connection string)"
    echo ""
    echo "📝 Edit the .env file now, then run this script again with --start"
    echo ""
    echo "For detailed setup instructions, see: INSTALLATION_GUIDE.md"
    exit 0
else
    echo "✅ Environment file found"
fi

# Check if --start flag is provided
if [ "$1" = "--start" ]; then
    echo "🚀 Starting Discord AI Moderator..."
    
    # Create logs directory if it doesn't exist
    mkdir -p logs
    
    # Start the bot
    npm start
else
    echo ""
    echo "🎯 Next steps:"
    echo "1. Edit the .env file with your tokens and configuration"
    echo "2. Run: ./scripts/deploy.sh --start"
    echo ""
    echo "For detailed setup help, see: INSTALLATION_GUIDE.md"
fi