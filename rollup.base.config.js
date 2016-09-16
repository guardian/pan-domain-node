import babel from 'rollup-plugin-babel';
import commonjs from 'rollup-plugin-commonjs';
import nodeResolve from 'rollup-plugin-node-resolve';

export default {
	entry: 'lib/index.js',
	plugins: [
        nodeResolve({
            jsnext: true,
            main: true,
            preferBuiltins: true
        }),
        commonjs(),
        babel({
            babelrc: false,
            presets: ['es2015-rollup']
        })
    ]
};
