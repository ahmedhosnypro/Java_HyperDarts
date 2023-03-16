
class Solution {
    ProductDTO convertProductToDTO(Product product) {
        return new ProductDTO(product.getId(), product.getModel(), product.getPrice());
    }
}