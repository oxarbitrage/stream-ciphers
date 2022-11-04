use cipher::{
    consts::{U1, U64},
    generic_array::typenum::Unsigned,
    Block, BlockSizeUser, ParBlocksSizeUser, StreamBackend,
    StreamCipherSeekCore,
};

// Bakends ssed2 chacha
/*
struct Backend<R: Unsigned> {
    v: [__m128i; 4],
    _pd: PhantomData<R>,
}

impl<R: Unsigned> BlockSizeUser for Backend<R> {
    type BlockSize = U64;
}

impl<R: Unsigned> ParBlocksSizeUser for Backend<R> {
    type ParBlocksSize = U1;
}
 */


use crate::SalsaCore;
//use crate::STATE_WORDS;

// soft version
pub struct Backend<'a, R: Unsigned>(pub &'a mut SalsaCore<R>);

impl<'a, R: Unsigned> BlockSizeUser for Backend<'a, R> {
    type BlockSize = U64;
}

impl<'a, R: Unsigned> ParBlocksSizeUser for Backend<'a, R> {
    type ParBlocksSize = U1;
}



impl<'a, R: Unsigned> StreamBackend for Backend<'a, R> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        let res = run_rounds::<R>(&self.0.state);
        self.0.set_block_pos(self.0.get_block_pos() + 1);

        for (chunk, val) in block.chunks_exact_mut(4).zip(res.iter()) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }
    }
}