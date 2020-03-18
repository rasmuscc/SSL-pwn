package abstractfactories;

import strategyimplementations.CBCModeStrategy;
import strategyimplementations.DummyPaddingStrategy;
import strategyinterfaces.ModeStrategy;
import strategyinterfaces.PaddingStrategy;

public class NormalCBCMode implements AbstractFactory {
	@Override
	public ModeStrategy getModeStrategy() {
		return new CBCModeStrategy(new DummyPaddingStrategy());
	}

	@Override
	public PaddingStrategy getPaddingStrategy() {
		return new DummyPaddingStrategy();
	}
}
