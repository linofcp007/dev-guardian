// Order totals for the checkout page.
function orderTotal(cart) {
  return cart.items.reduce((sum, item) => sum + item.price * item.qty);
}

module.exports = { orderTotal };
