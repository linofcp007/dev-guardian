const express = require('express');
const { orderTotal } = require('./cart');

const app = express();
app.use(express.json());

app.post('/api/checkout', (req, res) => {
  res.json({ total: orderTotal(req.body) });
});

app.listen(3000);
