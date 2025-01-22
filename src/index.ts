import express from 'express'
import { createHmac } from 'crypto'
import env from 'dotenv'

env.config()

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000
const channelSecret = process.env.LINE_CHANNEL_SECRET
if (!channelSecret) {
  console.error('Please set LINE_CHANNEL_SECRET')
  process.exit(1)
}

const forwardEndpoints = [
  'https://{your-endpoint-1}',
  'https://{your-endpoint-2}',
]

const app = express()

app.use((req, res, next) => {
  if (req.originalUrl === '/webhook') {
    express.raw({ type: 'application/json' })(req, res, next)
  } else {
    express.json()(req, res, next)
  }
})

const verifyWebhook = (signature: string, body: Buffer) => {
  const hash = createHmac('SHA256', channelSecret)
    .update(body)
    .digest('base64')
    .toString()

  if (hash !== signature) {
    console.log('Signature do not match')
    return false
  }

  console.log('Signature matched')
  return hash === signature
}

app.post('/webhook', async (req, res) => {
  const signature = req.get('X-Line-Signature')
  const userAgent = req.get('User-Agent') || ''
  if (!signature) {
    res.status(401).json({ message: 'Missing Signature' })
    return
  }

  if (!verifyWebhook(signature, req.body)) {
    res.status(401).json({ message: 'Invalid Signature' })
    return
  }

  await Promise.all(
    forwardEndpoints.map(async (endpoint) => {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Line-Signature': signature,
          'User-Agent': userAgent,
        },
        body: req.body,
      })
      console.log(`Forwarded to ${endpoint} with status ${response.status}`)
    }),
  )

  res.status(202).json({ message: 'Webhook received with verified signaure' })
})

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})
