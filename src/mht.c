#include <bftvmhors/format.h>
#include <bftvmhors/hash.h>
#include <bftvmhors/mht.h>
#include <bftvmhors/stack.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#define MHT_NODE_TYPE_LEAF 0
#define MHT_NODE_TYPE_NON_LEAF 1

static mht_node_t *mht_new_node(const u8 *input, u32 length, u32 level,
                                u32 node_type) {
    mht_node_t *new_node = malloc(sizeof(mht_node_t));
    new_node->level = level;

    if (node_type == MHT_NODE_TYPE_LEAF) {
        /* Hash the input */
        u8 hash_value[HASH_MAX_LENGTH_THRESHOLD];
        u32 hash_size = ltc_hash_sha2_256(hash_value, input, length);
        new_node->data_size = hash_size;
        new_node->data = malloc(hash_size);
        memcpy(new_node->data, hash_value, hash_size);
    } else {
        new_node->data_size = length;
        new_node->data = malloc(length);
        memcpy(new_node->data, input, length);
    }
    return new_node;
}

static mht_node_t *mht_merge_nodes(const mht_node_t *left_node,
                                   const mht_node_t *right_node) {
    /* Concat the data from the left and right nodes */
    u8 *concat_buffer = malloc(left_node->data_size + right_node->data_size);
    u32 concat_length = concat_buffers(concat_buffer, left_node->data, left_node->data_size,
                           right_node->data, right_node->data_size);

    /* Hash the concat_buffer */
    u8 hash_value[HASH_MAX_LENGTH_THRESHOLD];
    u32 hash_size = ltc_hash_sha2_256(hash_value, concat_buffer, concat_length);

    /* Creating a new MHT node */
    mht_node_t *new_node = mht_new_node(
            hash_value, hash_size, left_node->level + 1, MHT_NODE_TYPE_NON_LEAF);

    free(concat_buffer);
    return new_node;
}

void mht_destroy_node(mht_node_t *node) {
    free(node->data);
    free(node);
}

mht_node_t *mht_build(const u8 *input, u32 num_blocks, u32 block_size) {
    /* Allocating a new stack and initialize it with the num_blocks capacity */
    stack_t stack;
    stack_init(&stack, num_blocks + 1);

    for (u32 i = 0; i < num_blocks; i++) {
        /* Create a leaf node and push it to the stack */
        mht_node_t *node =
                mht_new_node(input + i * block_size, block_size, 0, MHT_NODE_TYPE_LEAF);
        stack_push(&stack, (void *)node);

        while (stack_getsize(&stack) >= 2) {
            /* Stack has at least two elements. Pop the first two and check if they
             * are in the same level */
            mht_node_t *left_node = (mht_node_t *)stack_pop(&stack);
            mht_node_t *right_node = (mht_node_t *)stack_top(
                    &stack);  // Using top instead of pop for efficiency
            if (left_node->level == right_node->level) {
                /* Merge the left and right nodes and push back to the stack */
                right_node = (mht_node_t *)stack_pop(&stack);  // Pop the right node
                mht_node_t *new_node = mht_merge_nodes(left_node, right_node);

                /* Deleting the previous nodes */
                mht_destroy_node(left_node);
                mht_destroy_node(right_node);

                /* If we have reached the root */
                if (new_node->level == log2(num_blocks)) return new_node;

                stack_push(&stack, (void *)new_node);
            } else {
                /* Push back the nodes to the stack. We have only popped the left_node
                 */
                stack_push(&stack, (void *)left_node);
                break;
            }
        }
    }
}