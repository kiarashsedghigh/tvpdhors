#ifndef BFTVMHORS_MHT_H
#define BFTVMHORS_MHT_H

#include <bftvmhors/types.h>

typedef struct mht_node{
    void * data;
    u32 data_size;
    u32 level;
}mht_node_t;


/// Build a MHT upon the given input
/// \param input Pointer to the input
/// \param num_blocks Number of blocks in the input
/// \param block_size Size of each block in the input
/// \return MHT root node
mht_node_t *mht_build(const u8 *input, u32 num_blocks, u32 block_size);


/// Destroys the MHT node
/// \param node Pointer to the MHT node
void mht_destroy_node(mht_node_t *node);

#endif