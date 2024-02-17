#include <bftvmhors/stack.h>
#include <stdlib.h>


void stack_init(stack_t * stack, u32 size) {
    stack->data = malloc(sizeof(void *)*size);
    stack->capacity = size;
    stack->length = 0;
}


u32 stack_push(stack_t * stack, void * element){
    if (stack->length == stack->capacity)
        return STACK_PUSH_FAILED;

    stack->data[stack->length] = element;
    stack->length++;
    return STACK_PUSH_SUCCESS;
}

void * stack_pop(stack_t * stack){
    if (stack->length == 0)
        return STACK_POP_FAILED;

    stack->length--;
    return stack->data[stack->length];
}

void * stack_top(stack_t * stack){
    if (stack->length == 0)
        return STACK_TOP_FAILED;

    return stack->data[stack->length-1];
}

u32 stack_getsize(stack_t * stack){
    return stack->length;
}

