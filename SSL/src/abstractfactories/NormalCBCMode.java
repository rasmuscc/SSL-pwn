package abstractfactories;

import strategyimplementations.CBCModeStrategy;
import strategyimplementations.PKCS7PaddingStrategy;
import strategyinterfaces.ModeStrategy;
import strategyinterfaces.PaddingStrategy;

public class NormalCBCMode implements AbstractFactory {
	@Override
	public ModeStrategy getModeStrategy() {
		return new CBCModeStrategy(new PKCS7PaddingStrategy());
	}

	@Override
	public PaddingStrategy getPaddingStrategy() {
		return new PKCS7PaddingStrategy();
	}
}
