import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { Octokit } from '@octokit/rest';
import Anthropic from '@anthropic-ai/sdk';

const app = express();

// Load environment variables
const {
  GITHUB_APP_ID,
  GITHUB_PRIVATE_KEY,
  GITHUB_WEBHOOK_SECRET,
  ANTHROPIC_API_KEY,
  PORT = 3000
} = process.env;

// Validate required environment variables
if (!GITHUB_APP_ID || !GITHUB_PRIVATE_KEY || !GITHUB_WEBHOOK_SECRET || !ANTHROPIC_API_KEY) {
  console.error('Missing required environment variables');
  process.exit(1);
}

// Initialize Anthropic client
const anthropic = new Anthropic({
  apiKey: ANTHROPIC_API_KEY
});

// Middleware to parse JSON body
app.use(express.json());

/**
 * Verify GitHub webhook signature
 */
function verifySignature(payload, signature) {
  if (!signature) {
    return false;
  }

  const hmac = crypto.createHmac('sha256', GITHUB_WEBHOOK_SECRET);
  const digest = 'sha256=' + hmac.update(JSON.stringify(payload)).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
}

/**
 * Generate JWT for GitHub App authentication
 */
function generateJWT() {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      iat: now - 60, // Issued at time (1 minute ago to account for clock skew)
      exp: now + 600, // Expires in 10 minutes
      iss: GITHUB_APP_ID // GitHub App ID (required for GitHub App JWT)
    },
    GITHUB_PRIVATE_KEY.replace(/\\n/g, '\n'),
    { algorithm: 'RS256' }
  );
}

/**
 * Get installation access token
 */
async function getInstallationToken(installationId) {
  const token = generateJWT();
  const octokit = new Octokit({
    auth: token
  });

  const { data } = await octokit.rest.apps.createInstallationAccessToken({
    installation_id: installationId
  });

  return data.token;
}

/**
 * Read guidelines file from repository
 */
async function readGuidelines(octokit, owner, repo) {
  const paths = ['.ai/guidelines.md', '.github/ai-guidelines.md'];

  for (const path of paths) {
    try {
      const { data } = await octokit.rest.repos.getContent({
        owner,
        repo,
        path
      });

      if (data.type === 'file' && data.encoding === 'base64') {
        return Buffer.from(data.content, 'base64').toString('utf-8');
      }
    } catch (error) {
      // File not found, continue to next path
      if (error.status !== 404) {
        console.error(`Error reading guidelines from ${path}:`, error.message);
      }
    }
  }

  return null;
}

/**
 * Get repository file tree using Git Tree API (1 call, more efficient)
 */
async function getFileTree(octokit, owner, repo) {
  try {
    // 1. Get repo to discover default branch
    const { data: repoData } = await octokit.rest.repos.get({
      owner,
      repo
    });

    const defaultBranch = repoData.default_branch;

    // 2. Get the commit SHA of the default branch
    const { data: refData } = await octokit.rest.git.getRef({
      owner,
      repo,
      ref: `heads/${defaultBranch}`
    });

    // 3. Get the tree recursively
    const { data: treeData } = await octokit.rest.git.getTree({
      owner,
      repo,
      tree_sha: refData.object.sha,
      recursive: '1'
    });

    return treeData.tree
      .filter(item => item.type === 'blob')
      .map(item => item.path)
      .sort();
  } catch (error) {
    console.error('Error fetching file tree:', error.message);
    return [];
  }
}

/**
 * Call Claude API to analyze the issue
 */
async function analyzeIssue(issueTitle, issueBody, fileTree) {
  const systemPrompt = `You are a senior software engineer reviewing GitHub issues. Analyze issues pragmatically and avoid hallucinations. Be concise and structured in your responses.

Always respond in markdown format with the following sections:
1. **Missing Information** - List any critical information that is missing from the issue
2. **Classification** - Classify as: bug / feature / improvement
3. **Analysis or Plan** - Provide analysis of the problem or a suggested execution plan
4. **Relevant Files** - List files from the repository that are likely relevant to this issue`;

  const userPrompt = `Analyze this GitHub issue:

**Title:** ${issueTitle}

**Body:**
${issueBody}

**Repository Files:**
${fileTree.length > 0 ? fileTree.slice(0, 200).join('\n') : 'No files found'}
${fileTree.length > 200 ? `\n... and ${fileTree.length - 200} more files` : ''}`;

  try {
    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-5-20250929',
      max_tokens: 2000,
      system: systemPrompt,
      messages: [
        {
          role: 'user',
          content: userPrompt
        }
      ]
    });

    return message.content[0].text;
  } catch (error) {
    console.error('Claude API error:', error.message);
    throw error;
  }
}

/**
 * Main webhook handler
 */
app.post('/webhook', async (req, res) => {
  console.log('[Webhook] Received webhook request');
  
  // Verify webhook signature
  const signature = req.headers['x-hub-signature-256'];
  if (!verifySignature(req.body, signature)) {
    console.log('[Webhook] Invalid signature');
    return res.status(401).send('Invalid signature');
  }
  console.log('[Webhook] Signature verified');

  const { action, comment, issue, installation, repository } = req.body;
  const eventType = req.headers['x-github-event'];
  console.log(`[Webhook] Event type: ${eventType}, Action: ${action}`);

  // Only process issue_comment events
  if (eventType !== 'issue_comment') {
    console.log(`[Webhook] Ignoring event type: ${eventType}`);
    return res.status(200).send('Event ignored');
  }

  // Only process when comment is created and contains @claude-judge
  const commentBody = comment?.body || '';
  const hasCommand = commentBody.includes('@claude-judge');
  console.log(`[Webhook] Comment body preview: ${commentBody.substring(0, 100)}...`);
  console.log(`[Webhook] Contains @claude-judge: ${hasCommand}`);
  
  if (action !== 'created' || !hasCommand) {
    console.log('[Webhook] Command not found or action not created');
    return res.status(200).send('Command not found');
  }

  // Early return if no installation ID
  if (!installation?.id) {
    console.log('[Webhook] Missing installation ID');
    return res.status(400).send('Missing installation ID');
  }
  console.log(`[Webhook] Installation ID: ${installation.id}`);

  try {
    const owner = repository.owner.login;
    const repo = repository.name;
    const issueNumber = issue.number;
    console.log(`[Webhook] Processing issue #${issueNumber} in ${owner}/${repo}`);

    // Log link to files endpoint
    const protocol = req.protocol || 'http';
    const host = req.get('host') || `localhost:${PORT}`;
    const filesUrl = `${protocol}://${host}/files?owner=${encodeURIComponent(owner)}&repo=${encodeURIComponent(repo)}&installation_id=${installation.id}`;
    console.log(`[Webhook] Files endpoint URL: ${filesUrl}`);

    // Get installation access token
    console.log('[Webhook] Generating installation access token...');
    const installationToken = await getInstallationToken(installation.id);
    console.log('[Webhook] Installation token obtained');

    // Create authenticated Octokit client
    const octokit = new Octokit({
      auth: installationToken
    });

    // Fetch issue details
    console.log('[Webhook] Fetching issue details...');
    const { data: issueData } = await octokit.rest.issues.get({
      owner,
      repo,
      issue_number: issueNumber
    });
    console.log(`[Webhook] Issue title: ${issueData.title}`);

    // Get repository file tree
    console.log('[Webhook] Fetching repository file tree...');
    const fileTree = await getFileTree(octokit, owner, repo);
    console.log(`[Webhook] Found ${fileTree.length} files in repository`);

    // Analyze issue with Claude
    console.log('[Webhook] Calling Claude API for analysis...');
    const analysis = await analyzeIssue(
      issueData.title,
      issueData.body || '',
      fileTree
    );
    console.log(`[Webhook] Analysis completed (${analysis.length} characters)`);

    // Post comment back to issue
    console.log('[Webhook] Posting comment to issue...');
    await octokit.rest.issues.createComment({
      owner,
      repo,
      issue_number: issueNumber,
      body: analysis
    });
    console.log('[Webhook] Comment posted successfully');

    res.status(200).send('Analysis completed');
  } catch (error) {
    console.error('[Webhook] Error processing webhook:', error);
    console.error('[Webhook] Error stack:', error.stack);
    res.status(500).send('Internal server error');
  }
});

/**
 * Endpoint to get repository file tree (debug only, not available in production)
 * GET /files?owner=OWNER&repo=REPO&installation_id=INSTALLATION_ID
 */
if (process.env.NODE_ENV !== 'production') {
  app.get('/files', async (req, res) => {
    const { owner, repo, installation_id } = req.query;
    
    console.log(`[Files] Request received for ${owner}/${repo}, installation: ${installation_id}`);
    
    if (!owner || !repo || !installation_id) {
      return res.status(400).json({
        error: 'Missing required parameters',
        required: ['owner', 'repo', 'installation_id']
      });
    }

    try {
      // Get installation access token
      console.log('[Files] Generating installation access token...');
      const installationToken = await getInstallationToken(parseInt(installation_id, 10));
      console.log('[Files] Installation token obtained');

      // Create authenticated Octokit client
      const octokit = new Octokit({
        auth: installationToken
      });

      // Get repository file tree
      console.log('[Files] Fetching repository file tree...');
      const fileTree = await getFileTree(octokit, owner, repo);
      console.log(`[Files] Found ${fileTree.length} files`);

      res.status(200).json({
        owner,
        repo,
        fileCount: fileTree.length,
        files: fileTree
      });
    } catch (error) {
      console.error('[Files] Error fetching file tree:', error);
      console.error('[Files] Error stack:', error.stack);
      res.status(500).json({
        error: 'Failed to fetch file tree',
        message: error.message
      });
    }
  });
} else {
  app.get('/files', (_, res) => {
    res.status(404).send('Not available');
  });
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

