/**
 * Tony Givargis
 * Copyright (C), 2023
 * University of California, Irvine
 *
 * CS 238P - Operating Systems
 * avl.c
 */

#include "scm.h"
#include "avl.h"

struct avl
{
	struct state
	{
		uint64_t items;
		uint64_t unique;
		struct node
		{
			int depth;
			uint64_t count;
			const char *item;
			struct node *left;
			struct node *right;
		} *root;
	} *state; /* SCM */
	struct scm *scm;
};

static int
delta(const struct node *node)
{
	return node ? node->depth : -1;
}

static int
balance(const struct node *node)
{
	return delta(node->left) - delta(node->right);
}

static int
depth(const struct node *a, const struct node *b)
{
	return (delta(a) > delta(b)) ? (delta(a) + 1) : (delta(b) + 1);
}

static struct node *
rotate_right(struct node *node)
{
	struct node *root;

	root = node->left;
	node->left = root->right;
	root->right = node;
	node->depth = depth(node->left, node->right);
	root->depth = depth(root->left, node);
	return root;
}

static struct node *
rotate_left(struct node *node)
{
	struct node *root;

	root = node->right;
	node->right = root->left;
	root->left = node;
	node->depth = depth(node->left, node->right);
	root->depth = depth(root->right, node);
	return root;
}

static struct node *
rotate_left_right(struct node *node)
{
	node->left = rotate_left(node->left);
	return rotate_right(node);
}

static struct node *
rotate_right_left(struct node *node)
{
	node->right = rotate_right(node->right);
	return rotate_left(node);
}

static struct node *
update(struct avl *avl, struct node *root, const char *item)
{
	int d;

	if (!root)
	{
		if (!(root = scm_malloc(avl->scm, sizeof(struct node))))
		{
			TRACE(0);
			return NULL;
		}
		memset(root, 0, sizeof(struct node));
		if (!(root->item = scm_strdup(avl->scm, item)))
		{
			TRACE(0);
			return NULL;
		}
		++root->count;
		++avl->state->items;
		++avl->state->unique;
		return root;
	}
	if (!(d = strcmp(item, root->item)))
	{
		++root->count;
		++avl->state->items;
	}
	else if (0 > d)
	{
		root->left = update(avl, root->left, item);
		if (1 < abs(balance(root)))
		{
			if (0 > strcmp(item, root->left->item))
			{
				root = rotate_right(root);
			}
			else
			{
				root = rotate_left_right(root);
			}
		}
	}
	else if (0 < d)
	{
		root->right = update(avl, root->right, item);
		if (1 < abs(balance(root)))
		{
			if (0 < strcmp(item, root->right->item))
			{
				root = rotate_left(root);
			}
			else
			{
				root = rotate_right_left(root);
			}
		}
	}
	root->depth = depth(root->left, root->right);
	return root;
}

static void
traverse(struct node *node, avl_fnc_t fnc, void *arg)
{
	if (node)
	{
		traverse(node->left, fnc, arg);
		fnc(arg, node->item, node->count);
		traverse(node->right, fnc, arg);
	}
}

struct avl *
avl_open(const char *pathname, int truncate)
{
	struct avl *avl;

	assert(pathname);

	if (!(avl = malloc(sizeof(struct avl))))
	{
		TRACE("out of memory");
		return NULL;
	}
	memset(avl, 0, sizeof(struct avl));
	if (!(avl->scm = scm_open(pathname, truncate)))
	{
		avl_close(avl);
		TRACE(0);
		return NULL;
	}
	if (scm_utilized(avl->scm))
	{
		avl->state = scm_mbase(avl->scm);
	}
	else
	{
		if (!(avl->state = scm_malloc(avl->scm,
																	sizeof(struct state))))
		{
			avl_close(avl);
			TRACE(0);
			return NULL;
		}
		memset(avl->state, 0, sizeof(struct state));
<<<<<<< Updated upstream
		assert(avl->state == scm_mbase(avl->scm));
=======
		/* assert(avl->state == scm_mbase(avl->scm)); */
>>>>>>> Stashed changes
	}
	return avl;
}

void avl_close(struct avl *avl)
{
	if (avl)
	{
		scm_close(avl->scm);
		memset(avl, 0, sizeof(struct avl));
	}
	FREE(avl);
}

int avl_insert(struct avl *avl, const char *item)
{
	struct node *root;

	assert(avl);
	assert(safe_strlen(item));

	if (!(root = update(avl, avl->state->root, item)))
	{
		TRACE(0);
		return -1;
	}
	avl->state->root = root;
	return 0;
}

static struct node *
remove_left(struct node *root)
{
	struct node *ptr = root;
	struct node *next;

	/* Initial check */
	if (!ptr->right)
	{
<<<<<<< Updated upstream
		return ptr->left;
=======
		return ptr;
>>>>>>> Stashed changes
	}

	/* Get the rightmost node */
	while (ptr->right->right)
	{
		ptr = ptr->right;
	}

	next = ptr->right->left;
	ptr->right->left = root;
<<<<<<< Updated upstream
	root = ptr->right->left;
	ptr->right = next;

=======
	root = ptr->right;
	ptr->right = next;

	root->depth = depth(root->left, root->right);
	ptr->depth = depth(ptr->left, ptr->right);

>>>>>>> Stashed changes
	return root;
}

static struct node *
remove_right(struct node *root)
{
	struct node *ptr = root;
	struct node *next;

	/* Initial check */
	if (!ptr->left)
	{
<<<<<<< Updated upstream
		return ptr->right;
	}

=======
		return ptr;
	}

	TRACE("Here now");

>>>>>>> Stashed changes
	/* Get the leftmost node */
	while (ptr->left->left)
	{
		ptr = ptr->left;
	}

<<<<<<< Updated upstream
	next = ptr->left->right;
	ptr->left->right = root;
	root = ptr->left->right;
	ptr->left = next;

=======
	TRACE("Now here");

	next = ptr->left->right;
	ptr->left->right = root;
	root = ptr->left;
	ptr->left = next;

	root->depth = depth(root->left, root->right);
	ptr->depth = depth(ptr->left, ptr->right);

>>>>>>> Stashed changes
	return root;
}

static struct node *
<<<<<<< Updated upstream
remove(struct avl *avl, struct node *root, const char *item)
=======
remove_node(struct avl *avl, struct node *root, const char *item)
>>>>>>> Stashed changes
{
	struct node *ptr;

	if (!root)
	{
		return NULL;
	}

	if (strcmp(item, root->item) == 0)
	{
		if (root->count > 1)
		{
			root->count--;
<<<<<<< Updated upstream
=======
			avl->state->items--;
>>>>>>> Stashed changes
			return root;
		}

		if (!root->left)
		{
			ptr = root->right;
<<<<<<< Updated upstream
			scm_free(avl->scm, root->item);
			scm_free(avl->scm, root);
=======
			scm_free(avl->scm, &root->item);
			scm_free(avl->scm, root);
			avl->state->items--;
			avl->state->unique--;
>>>>>>> Stashed changes
			return ptr;
		}
		if (!root->right)
		{
			ptr = root->left;
<<<<<<< Updated upstream
			scm_free(avl->scm, root->item);
			scm_free(avl->scm, root);
=======
			scm_free(avl->scm, &root->item);
			scm_free(avl->scm, root);
			avl->state->items--;
			avl->state->unique--;
>>>>>>> Stashed changes
			return ptr;
		}

		/* Determine the depth difference */
<<<<<<< Updated upstream
		if (root->left->depth > root->right->depth)
		{
			/* Left side is heavier */
			ptr = remove_left(ptr->left);
=======
		if (balance(root) < 0)
		{
			/* Left side is heavier */
			ptr = remove_left(root->left);
>>>>>>> Stashed changes
			ptr->right = root->right;
		}
		else
		{
<<<<<<< Updated upstream
			/* Right side is heavier, or equal */
			ptr = remove_right(ptr->right);
			ptr->left = root->left;
		}

		scm_free(avl->scm, root->item);
		scm_free(avl->scm, root);
=======
			TRACE("Rightleft");
			/* Right side is heavier, or equal */
			ptr = remove_right(root->right);
			ptr->left = root->left;
		}

		scm_free(avl->scm, &root->item);
		scm_free(avl->scm, root);
		avl->state->items--;
		avl->state->unique--;

>>>>>>> Stashed changes
		return ptr;
	}
	else if (strcmp(item, root->item) < 0)
	{
<<<<<<< Updated upstream
		root->left = remove(avl, root->left, item);
	}
	else
	{
		root->right = remove(avl, root->right, item);
	}

	return root;
}

int avl_remove(struct avl *acl, const char *item)
{
	struct node *root;
=======
		root->left = remove_node(avl, root->left, item);
	}
	else
	{
		root->right = remove_node(avl, root->right, item);
	}

	root->depth = depth(root->left, root->right);
	return root;
}

int avl_remove(struct avl *avl, const char *item)
{
	assert(avl);
	assert(safe_strlen(item));

	TRACE("Removing");

	avl->state->root = remove_node(avl, avl->state->root, item);
	return 0;
>>>>>>> Stashed changes
}

uint64_t
avl_exists(const struct avl *avl, const char *item)
{
	const struct node *node;
	int d;

	assert(avl);
	assert(safe_strlen(item));

	node = avl->state->root;
	while (node)
	{
		if (!(d = strcmp(item, node->item)))
		{
			return node->count;
		}
		node = (0 > d) ? node->left : node->right;
	}
	return 0;
}

void avl_traverse(const struct avl *avl, avl_fnc_t fnc, void *arg)
{
	assert(avl);
	assert(fnc);

	traverse(avl->state->root, fnc, arg);
}

uint64_t
avl_items(const struct avl *avl)
{
	assert(avl);

	return avl->state->items;
}

uint64_t
avl_unique(const struct avl *avl)
{
	assert(avl);

	return avl->state->unique;
}

size_t
avl_scm_utilized(const struct avl *avl)
{
	assert(avl);

	return scm_utilized(avl->scm);
}

size_t
avl_scm_capacity(const struct avl *avl)
{
	assert(avl);

	return scm_capacity(avl->scm);
}
