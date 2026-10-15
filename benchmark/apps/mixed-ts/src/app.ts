// TypeScript + template-literal + destructuring cases (mix of vuln and safe).
import express, { Request, Response } from 'express';
import { exec } from 'child_process';

const app = express();
app.use(express.json());

// VULN xss: template literal propagation (a classic miss for the original prototype)
app.get('/profile', (req: Request, res: Response) => {
  const name: string = req.query.name as string;
  res.send(`<section><h2>${name}</h2></section>`);
});

// VULN cmdi: destructured body field into exec
app.post('/convert', (req: Request, res: Response) => {
  const { filename } = req.body;
  exec(`convert ${filename} out.png`, (e, out) => res.send(out));
});

// SAFE: reassigned to a constant before the sink (no false positive)
app.get('/status', (req: Request, res: Response) => {
  let msg = req.query.msg as string;
  msg = 'ok';
  res.send(msg);
});

app.listen(3000);
export default app;
