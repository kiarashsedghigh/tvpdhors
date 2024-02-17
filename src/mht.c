#include <bftvmhors/format.h>
#include <bftvmhors/hash.h>
#include <bftvmhors/mht.h>
#include <bftvmhors/stack.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#define MHT_NODE_TYPE_LEAF 0
#define MHT_NODE_TYPE_NON_LEAF 1

static u32 compute_parent_id(u32 num_of_leaves, u32 child_id, u32 child_level){

    u32 tree_height = log2(num_of_leaves);

    u32 level_start, level_end, sum;

    if (child_level == 0){
        level_start = 1;
        level_end = num_of_leaves;
    }else {
        sum = 0;
        for (u32 j = 0; j < child_level; j++)
            sum += pow(2, tree_height - j);

        level_start = sum + 1;
        level_end = sum + pow(2, tree_height - child_level);
    }
    if (child_id % 2 == 0) child_id--;

    u32 parent_id = level_end + (child_id-level_start)/2 + 1;
    return parent_id;
}

static u32 generate_authentication_path_ids(u32 num_of_leaves, u32 leaf_id, u32 * id_list){
    /* Adding the first ID to the list, which is the leaf's sibling */
    *id_list++ = leaf_id % 2 == 0 ? leaf_id-1: leaf_id+1;

    u32 tree_height = log2(num_of_leaves);

    /* Starting from level 0 to the (top-1, non-root) level */
    for(u32 level=0; level < tree_height-1; level++){
        u32 parent_id = compute_parent_id(num_of_leaves, leaf_id, level);
        u32 uncle_id = parent_id % 2 == 0 ? parent_id-1: parent_id+1;
        leaf_id = parent_id;
        *id_list++ = uncle_id;
    }

    return tree_height;
}

static mht_node_t *mht_new_node(const u8 *input, u32 length, u32 level, u32 node_type, u32 id) {
    mht_node_t *new_node = malloc(sizeof(mht_node_t));
    new_node->level = level;

    if (node_type == MHT_NODE_TYPE_LEAF) {
        new_node->id = id;
        /* Hash the input */
        u8 hash_value[HASH_MAX_LENGTH_THRESHOLD];
        u32 hash_size = ltc_hash_sha2_256(hash_value, input, length);
        new_node->data_size = hash_size;
        new_node->data = malloc(hash_size);
        memcpy(new_node->data, hash_value, hash_size);
    } else {
        new_node->id = id;
        new_node->data_size = length;
        new_node->data = malloc(length);
        memcpy(new_node->data, input, length);
    }
    return new_node;
}

static mht_node_t *mht_merge_nodes(const mht_node_t *left_node, const mht_node_t *right_node, u32 num_of_leaves) {
    /* Concat the data from the left and right nodes */
    u8 *concat_buffer = malloc(left_node->data_size + right_node->data_size);
    u32 concat_length = concat_buffers(concat_buffer, left_node->data,left_node->data_size,
                                       right_node->data, right_node->data_size);

    /* Hash the concat_buffer as the new_node data */
    u8 hash_value[HASH_MAX_LENGTH_THRESHOLD];
    u32 hash_size = ltc_hash_sha2_256(hash_value, concat_buffer, concat_length);

    /* Compute the parent ID from the child */
    u32 parent_id = compute_parent_id(num_of_leaves, left_node->id, left_node->level);

    /* Creating a new MHT node */
    mht_node_t *new_node = mht_new_node(hash_value, hash_size, left_node->level + 1, MHT_NODE_TYPE_NON_LEAF, parent_id);

    free(concat_buffer);
    return new_node;
}

void mht_destroy_node(mht_node_t *node) {
    free(node->data);
    free(node);
}

mht_node_t *mht_build(const u8 *input, u32 num_blocks, u32 block_size, u32 do_generate_auth_path,
                      u32 auth_path_target_node, u8 * auth_path) {
    /* If we have to generate auth path */
    u32 *auth_path_nods_ids;
    u32 auth_path_idx;
    if (do_generate_auth_path == MHT_GENERATE_AUTH_PATH) {
        auth_path_nods_ids = malloc(sizeof(u32) * log2(num_blocks));
        auth_path_idx = 0;
        generate_authentication_path_ids(num_blocks, auth_path_target_node, auth_path_nods_ids);
    }

    /* Allocating a new stack and initialize it with the num_blocks capacity */
    stack_t stack;
    stack_init(&stack, num_blocks + 1);

    for (u32 i = 0; i < num_blocks; i++) {
        /* Create a leaf node and push it to the stack */
        mht_node_t *node = mht_new_node(input + i * block_size, block_size, 0, MHT_NODE_TYPE_LEAF, i+1);

        /* Check if this new node is in the path */
        if (do_generate_auth_path==MHT_GENERATE_AUTH_PATH && node->id == auth_path_nods_ids[auth_path_idx]){
            /* Node in the authentication path has been found */
            memcpy(auth_path, node->data, node->data_size);
            auth_path += node->data_size;
            auth_path_idx++;
        }

        stack_push(&stack, (void *)node);

        while (stack_getsize(&stack) >= 2) {
            /* Stack has at least two elements. Pop the first two and check if they
             * are in the same level */
            mht_node_t *left_node = (mht_node_t *)stack_pop(&stack);
            mht_node_t *right_node = (mht_node_t *)stack_top(&stack);  // Using top instead of pop for efficiency

            if (left_node->level == right_node->level) {
                /* Merge the left and right nodes and push back to the stack */
                right_node = (mht_node_t *)stack_pop(&stack);  // Pop the right node
                mht_node_t *merged_nodes = mht_merge_nodes(left_node, right_node, num_blocks);

                /* Check if this new node is in the path */
                if (do_generate_auth_path==MHT_GENERATE_AUTH_PATH && merged_nodes->id == auth_path_nods_ids[auth_path_idx]){
                    /* Node in the authentication path has been found */
                    memcpy(auth_path, merged_nodes->data, merged_nodes->data_size);
                    auth_path += merged_nodes->data_size;
                    auth_path_idx++;
                }

                /* Deleting the previous nodes */
                mht_destroy_node(left_node);
                mht_destroy_node(right_node);

                /* If we have reached the root */
                if (merged_nodes->level == log2(num_blocks)) return merged_nodes;

                stack_push(&stack, (void *)merged_nodes);
            } else {
                /* Push back the nodes to the stack. We have only popped the left_node
                 */
                stack_push(&stack, (void *)left_node);
                break;
            }
        }
    }

    free(auth_path_nods_ids);
}
